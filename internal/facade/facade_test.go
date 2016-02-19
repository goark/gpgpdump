package facade

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/spiegel-im-spiegel/gocli"
)

func GetUI(inpmsg string, outBuf, errBuf io.Writer) *gocli.UI {
	inBuf := strings.NewReader(inpmsg)
	return &gocli.UI{Reader: inBuf, Writer: outBuf, ErrorWriter: errBuf}
}

func TestRun(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"--ftest"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
}

func TestRunHflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"-h"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != nil {
		t.Errorf("facade.Run() = \"%v\", want nil.", err)
	}
	if !fcd.command.Hflag {
		t.Errorf("command.Hflag = %v", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
	if outBuf.Len() > 0 {
		t.Errorf("stdout = \"%v\", want empty.", outBuf)
	}
	if errBuf.Len() == 0 {
		t.Error("stderr = empty.")
	} else {
		fmt.Println(errBuf)
	}
}

func TestRunVflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, runtime.Version(), ui)
	args := []string{"-v"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != nil {
		t.Errorf("facade.Run() = \"%v\", want nil.", err)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if !fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
	if outBuf.Len() > 0 {
		t.Errorf("stdout = \"%v\", want empty.", outBuf)
	}
	if errBuf.Len() == 0 {
		t.Error("stderr = empty.")
	} else {
		fmt.Println(errBuf)
	}
}

func TestRunAflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"-ftest", "-a"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if !fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
}

func TestRunDflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"-ftest", "-d"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if !fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
}

func TestRunGflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"-ftest", "-g"}

	rtn, err := fcd.Run(args)
	if rtn == 0 {
		t.Errorf("facade.Run() = %v, want not 0.", rtn)
	}
	if err == ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want not \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
}

func TestRunIflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"-ftest", "-i"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if !fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
}

func TestRunJflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"-ftest", "-j"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if !fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
}

func TestRunLflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"-ftest", "-l"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if !fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
}

func TestRunMflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"-ftest", "-m"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if !fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
}

func TestRunPflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"-ftest", "-p"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if !fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
}

func TestRunUflag(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"-ftest", "-u"}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if !fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile != "" {
		t.Errorf("command.InputFile = \"%v\", want empty.", fcd.command.InputFile)
	}
}

func TestRunFile(t *testing.T) {
	name := "gpgpgdump"
	version := "0.0.0"
	fileName := "test.asc"
	inpmsg := ""
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	ui := GetUI(inpmsg, outBuf, errBuf)
	fcd := NewFacade(name, version, "", ui)
	args := []string{"--ftest", fileName}

	rtn, err := fcd.Run(args)
	if rtn != 0 {
		t.Errorf("facade.Run() = %v, want 0.", rtn)
	}
	if err != ErrFacadeTest {
		t.Errorf("facade.Run() = \"%v\", want \"%v\".", err, ErrFacadeTest)
	}
	if fcd.command.Hflag {
		t.Errorf("command.Hflag = %v.", fcd.command.Hflag)
	}
	if fcd.command.Vflag {
		t.Errorf("command.Vflag = %v.", fcd.command.Vflag)
	}
	if fcd.command.Aflag {
		t.Errorf("command.Aflag = %v.", fcd.command.Aflag)
	}
	if fcd.command.Dflag {
		t.Errorf("command.Dflag = %v.", fcd.command.Dflag)
	}
	if fcd.command.Gflag {
		t.Errorf("command.Gflag = %v.", fcd.command.Gflag)
	}
	if fcd.command.Iflag {
		t.Errorf("command.Iflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Jflag {
		t.Errorf("command.Jflag = %v.", fcd.command.Iflag)
	}
	if fcd.command.Lflag {
		t.Errorf("command.Lflag = %v.", fcd.command.Lflag)
	}
	if fcd.command.Mflag {
		t.Errorf("command.Mflag = %v.", fcd.command.Mflag)
	}
	if fcd.command.Pflag {
		t.Errorf("command.Pflag = %v.", fcd.command.Pflag)
	}
	if fcd.command.Uflag {
		t.Errorf("command.Uflag = %v.", fcd.command.Uflag)
	}
	if fcd.command.InputFile == "" {
		t.Errorf("command.InputFile = empty, want \"%v\".", fileName)
	}
}
