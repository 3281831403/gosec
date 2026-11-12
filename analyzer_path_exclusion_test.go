package gosec_test

import (
	"io"
	"log"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/rules"
)

const pathExclusionSource = `package main

import "fmt"

func main() {
	password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
	fmt.Println(password)
}
`

func newPathExclusionAnalyzer(showIgnored, trackSuppressions bool, roots ...string) *gosec.Analyzer {
	config := gosec.NewConfig()
	if showIgnored {
		config.SetGlobal(gosec.ShowIgnored, "true")
	}
	analyzer := gosec.NewAnalyzer(config, false, false, trackSuppressions, 1, log.New(io.Discard, "", 0))
	analyzer.LoadRules(rules.Generate(trackSuppressions).RulesInfo())

	filter, err := gosec.NewPathExclusionFilter([]gosec.PathExcludeRule{
		{Path: `^cmd/`, Rules: []string{"G101"}},
	})
	Expect(err).NotTo(HaveOccurred())
	filter.SetRoots(roots...)
	analyzer.SetPathExclusionFilter(filter)
	return analyzer
}

func createPathExclusionProject() string {
	root := GinkgoT().TempDir()
	for _, dir := range []string{"cmd", "pkg"} {
		Expect(os.MkdirAll(filepath.Join(root, dir), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(root, dir, "main.go"), []byte(pathExclusionSource), 0o600)).To(Succeed())
	}
	return root
}

var _ = Describe("Path-based exclude-rules suppressions", func() {
	It("hides matched findings by default and does not count them", func() {
		root := createPathExclusionProject()
		analyzer := newPathExclusionAnalyzer(false, false, root)

		Expect(analyzer.Process(nil, filepath.Join(root, "cmd"), filepath.Join(root, "pkg"))).To(Succeed())

		issues, metrics, _ := analyzer.Report()
		Expect(issues).To(HaveLen(1))
		Expect(issues[0].File).To(Equal(filepath.Join(root, "pkg", "main.go")))
		Expect(issues[0].RuleID).To(Equal("G101"))
		Expect(metrics.NumFound).To(Equal(1))
		for _, iss := range issues {
			Expect(iss.Suppressions).To(BeEmpty())
		}
	})

	It("shows matched findings with show-ignored without changing the found count", func() {
		root := createPathExclusionProject()
		analyzer := newPathExclusionAnalyzer(true, false, root)

		Expect(analyzer.Process(nil, filepath.Join(root, "cmd"), filepath.Join(root, "pkg"))).To(Succeed())

		issues, metrics, _ := analyzer.Report()
		Expect(issues).To(HaveLen(2))
		Expect(metrics.NumFound).To(Equal(1))

		var ignored, active *issue.Issue
		for _, iss := range issues {
			if iss.NoSec {
				ignored = iss
			} else {
				active = iss
			}
		}
		Expect(ignored).NotTo(BeNil())
		Expect(active).NotTo(BeNil())
		Expect(ignored.File).To(Equal(filepath.Join(root, "cmd", "main.go")))
		Expect(active.File).To(Equal(filepath.Join(root, "pkg", "main.go")))
		// Suppression detail is only attached when tracking is enabled.
		Expect(ignored.Suppressions).To(BeEmpty())
	})

	It("records matched findings as auditable external suppressions when tracking", func() {
		root := createPathExclusionProject()
		analyzer := newPathExclusionAnalyzer(false, true, root)

		Expect(analyzer.Process(nil, filepath.Join(root, "cmd"), filepath.Join(root, "pkg"))).To(Succeed())

		issues, metrics, _ := analyzer.Report()
		Expect(issues).To(HaveLen(2))
		Expect(metrics.NumFound).To(Equal(1))

		var suppressed *issue.Issue
		for _, iss := range issues {
			if len(iss.Suppressions) > 0 {
				suppressed = iss
			}
		}
		Expect(suppressed).NotTo(BeNil())
		Expect(suppressed.File).To(Equal(filepath.Join(root, "cmd", "main.go")))
		Expect(suppressed.Suppressions).To(HaveLen(1))
		Expect(suppressed.Suppressions[0].Kind).To(Equal("external"))
		Expect(suppressed.Suppressions[0].Path).To(Equal(`^cmd/`))
		Expect(suppressed.Suppressions[0].Rule).To(Equal("G101"))
		Expect(suppressed.Suppressions[0].Justification).NotTo(BeEmpty())
	})

	It("matches anchored patterns against absolute paths only when roots are configured", func() {
		root := createPathExclusionProject()

		// Without roots, the absolute path cannot match the anchored ^cmd/ pattern.
		analyzerWithoutRoots := newPathExclusionAnalyzer(false, false)
		Expect(analyzerWithoutRoots.Process(nil, filepath.Join(root, "cmd"))).To(Succeed())
		issues, _, _ := analyzerWithoutRoots.Report()
		Expect(issues).To(HaveLen(1))

		// With the scan root configured, the same absolute path is made
		// root-relative and the finding is suppressed.
		analyzerWithRoots := newPathExclusionAnalyzer(false, false, root)
		Expect(analyzerWithRoots.Process(nil, filepath.Join(root, "cmd"))).To(Succeed())
		issues, _, _ = analyzerWithRoots.Report()
		Expect(issues).To(BeEmpty())
	})

	It("keeps findings when no path exclusion filter is configured", func() {
		root := createPathExclusionProject()
		analyzer := gosec.NewAnalyzer(gosec.NewConfig(), false, false, true, 1,
			log.New(io.Discard, "", 0))
		analyzer.LoadRules(rules.Generate(true).RulesInfo())

		Expect(analyzer.Process(nil, filepath.Join(root, "cmd"))).To(Succeed())
		issues, _, _ := analyzer.Report()
		Expect(issues).To(HaveLen(1))
		Expect(issues[0].Suppressions).To(BeEmpty())
	})
})
