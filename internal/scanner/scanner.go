package scanner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/llm"
	"github.com/effective-security/promptviser/internal/scanner/pass1"
	"github.com/effective-security/promptviser/internal/scanner/pass2"
	pass3 "github.com/effective-security/promptviser/internal/scanner/pass3"
	"github.com/effective-security/promptviser/internal/scanner/pass4"
)

// promptExtensions lists the file extensions treated as prompt files.
var promptExtensions = map[string]bool{
	".yaml": true,
	".yml":  true,
	".txt":  true,
	".md":   true,
}

// sourceExtensions lists the file extensions searched when looking for source
// files that call or load a prompt file.
var sourceExtensions = map[string]bool{
	".go":   true,
	".py":   true,
	".js":   true,
	".ts":   true,
	".java": true,
}

// Result holds the combined output of all four passes for a scanned file.
type Result struct {
	FileName       string
	StaticTriggers []string
	MetadataFlags  []string
	Scores         []*pb.DimensionScore
}

// TODO: add a ScanConfig to configure what triggers get ignored
// type ScanConfig struct {
//     Extensions      []string            // default: .yaml,.yml,.txt,.md
//     ExcludeRules    map[string][]string // filename → rule IDs to suppress
// }
// TODO: later add compliance to other yaml config frameworks

// Scan walks dir, runs all four passes over every prompt file found, and
// returns the combined results. Prompt text never leaves this function.
//
// Each prompt file produces one FileScanResult. If source files that reference
// the prompt are found, each of those produces its own separate FileScanResult
// containing only ASTTriggers — enabling per-caller-file findings in the report.
func Scan(ctx context.Context, dir string, provider llm.Provider) ([]*pb.FileScanResult, error) {
	files, err := collectPromptFiles(dir)
	if err != nil {
		return nil, err
	}

	type batch struct {
		results []*pb.FileScanResult
		err     error
	}
	batchCh := make(chan batch, len(files))
	var wg sync.WaitGroup

	for _, path := range files {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			promptResult := &pb.FileScanResult{FileName: path}

			content, err := os.ReadFile(path)
			if err != nil {
				batchCh <- batch{err: err}
				return
			}

			// Pass 1: regex-based static analysis on the prompt text.
			pass1Triggers := pass1.Check(content)
			// Pass 2: YAML metadata flags.
			metadataFlags := pass2.Analyze(content)
			promptResult.StaticTriggers = enrichStaticTriggers(content, pass1Triggers, metadataFlags)
			promptResult.MetadataFlags = metadataFlags
			// Pass 3: AST analysis on source files that call this prompt.
			// Each caller that produces triggers becomes its own FileScanResult.
			callerResults := scanCallers(findCallerFiles(path, dir))
			// Pass 4: LLM scoring on the prompt itself.
			scores, err := pass4.Score(ctx, content, promptResult.StaticTriggers, promptResult.MetadataFlags, provider)
			if err != nil {
				scores = []*pb.DimensionScore{{Dimension: "error: " + err.Error(), Score: 1}}
			}
			promptResult.Scores = mergeScores(promptResult.Scores, scores)

			out := make([]*pb.FileScanResult, 0, 1+len(callerResults))
			out = append(out, promptResult)
			out = append(out, callerResults...)
			batchCh <- batch{results: out}
		}(path)
	}

	go func() {
		wg.Wait()
		close(batchCh)
	}()

	var all []*pb.FileScanResult
	for b := range batchCh {
		if b.err != nil {
			return nil, b.err
		}
		all = append(all, b.results...)
	}
	return all, nil
}

// scanCallers runs pass3 (AST analysis) on each caller file individually and
// returns a separate FileScanResult for every caller that produces triggers.
// Callers with no triggers are omitted to keep the output clean.
func scanCallers(callers []pass3.CallerFile) []*pb.FileScanResult {
	var results []*pb.FileScanResult
	for _, caller := range callers {
		triggers := pass3.Analyze([]pass3.CallerFile{caller})
		if len(triggers) == 0 {
			continue
		}
		results = append(results, &pb.FileScanResult{
			FileName:    caller.Path,
			ASTTriggers: triggers,
		})
	}
	return results
}

// findCallerFiles walks rootDir for source code files that reference promptPath
// by filename. A source file is considered a caller if its content contains the
// prompt's base name (e.g. "crisis-support.yaml"). Unreadable files are silently
// skipped — caller discovery is best-effort and never fails the scan.
func findCallerFiles(promptPath, rootDir string) []pass3.CallerFile {
	base := filepath.Base(promptPath) // e.g. "crisis-support.yaml"
	needle := []byte(base)

	var callers []pass3.CallerFile
	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != rootDir {
				return filepath.SkipDir
			}
			return nil
		}
		if !sourceExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if bytes.Contains(content, needle) {
			callers = append(callers, pass3.CallerFile{Path: path, Content: content})
		}
		return nil
	})
	return callers
}

// collectPromptFiles returns all prompt files under dir recursively.
func collectPromptFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// skip hidden dirs like .git
			if strings.HasPrefix(d.Name(), ".") && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if promptExtensions[strings.ToLower(filepath.Ext(path))] {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// mergeScores averages duplicate dimensions across files so the server
// receives one score per dimension regardless of how many files were scanned.
func enrichStaticTriggers(content []byte, initial []string, metadataFlags []string) []string {
	triggered := make(map[string]struct{}, len(initial)+2)
	for _, trigger := range initial {
		triggered[trigger] = struct{}{}
	}

	if shouldFlagMissingAIIdentity(content, metadataFlags) {
		triggered["MISSING_AI_DISCLOSURE"] = struct{}{}
	}
	if shouldFlagMissingFormatInstruction(content) {
		triggered["MISSING_FORMAT_INSTRUCTION"] = struct{}{}
	}

	out := make([]string, 0, len(triggered))
	for trigger := range triggered {
		out = append(out, trigger)
	}
	return out
}

func shouldFlagMissingAIIdentity(content []byte, metadataFlags []string) bool {
	if !hasMetadataFlag(metadataFlags, "is_user_facing") {
		return false
	}

	lower := bytes.ToLower(content)
	if bytes.Contains(lower, []byte("i am an ai")) || bytes.Contains(lower, []byte("i am a language model")) ||
		bytes.Contains(lower, []byte("i'm an ai")) || bytes.Contains(lower, []byte("i'm a language model")) ||
		bytes.Contains(lower, []byte("ai assistant")) || bytes.Contains(lower, []byte("ai chatbot")) ||
		bytes.Contains(lower, []byte("language model")) || bytes.Contains(lower, []byte("you are not a human")) {
		return false
	}
	return true
}

func shouldFlagMissingFormatInstruction(content []byte) bool {
	lower := bytes.ToLower(content)
	if !bytes.Contains(lower, []byte("answer")) && !bytes.Contains(lower, []byte("respond")) && !bytes.Contains(lower, []byte("reply")) {
		return false
	}
	for _, hint := range []string{"format", "structure", "bullet", "paragraph", "sentence", "json", "plain text", "list", "table"} {
		if bytes.Contains(lower, []byte(hint)) {
			return false
		}
	}
	return true
}

func hasMetadataFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if flag == want {
			return true
		}
	}
	return false
}

func mergeScores(existing, incoming []*pb.DimensionScore) []*pb.DimensionScore {
	index := make(map[string]int, len(existing))
	counts := make(map[string]int, len(existing))
	out := make([]*pb.DimensionScore, len(existing))
	copy(out, existing)

	for i, s := range out {
		index[s.Dimension] = i
		counts[s.Dimension] = 1
	}

	for _, s := range incoming {
		if i, ok := index[s.Dimension]; ok {
			n := float32(counts[s.Dimension])
			out[i].Score = (out[i].Score*n + s.Score) / (n + 1)
			counts[s.Dimension]++
		} else {
			index[s.Dimension] = len(out)
			counts[s.Dimension] = 1
			out = append(out, &pb.DimensionScore{
				Dimension: s.Dimension,
				Score:     s.Score,
			})
		}
	}
	return out
}
