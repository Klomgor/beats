// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package unittest

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/magefile/mage/mg"

	devtools "github.com/elastic/beats/v7/dev-tools/mage"
	"github.com/elastic/beats/v7/dev-tools/mage/target/test"
)

func init() {
	test.RegisterDeps(UnitTest)
}

var (
	goTestDeps, pythonTestDeps []interface{}
)

// RegisterGoTestDeps registers dependencies of the GoUnitTest target.
func RegisterGoTestDeps(deps ...interface{}) {
	goTestDeps = append(goTestDeps, deps...)
}

// RegisterPythonTestDeps registers dependencies of the PythonUnitTest target.
func RegisterPythonTestDeps(deps ...interface{}) {
	pythonTestDeps = append(pythonTestDeps, deps...)
}

// UnitTest executes the unit tests (Go and Python).
func UnitTest() {
	mg.SerialDeps(GoUnitTest, PythonUnitTest)
}

// GoFIPSOnlyUnitTest sets GODEBUG=fips140=only when running unit tests
func GoFIPSOnlyUnitTest() error {
	ctx := context.Background()
	mg.SerialCtxDeps(ctx, goTestDeps...)

	fipsArgs := devtools.DefaultGoFIPSOnlyTestArgs()
	return devtools.GoTest(ctx, fipsArgs)
}

// GoUnitTest executes the Go unit tests.
// Use TEST_COVERAGE=true to enable code coverage profiling.
// Use RACE_DETECTOR=true to enable the race detector.
func GoUnitTest(ctx context.Context) error {
	mg.SerialCtxDeps(ctx, goTestDeps...)

	utArgs := devtools.DefaultGoTestUnitArgs()
	// If synthetics is installed run synthetics unit tests
	synth := exec.Command("npx", "@elastic/synthetics", "-h")
	if synth.Run() == nil {
		fmt.Printf("npx @elastic/synthetics found, will run with synthetics tags")
		utArgs.Tags = append(utArgs.Tags, "synthetics")
	}
	return devtools.GoTest(ctx, utArgs)
}

// PythonUnitTest executes the python system tests.
func PythonUnitTest() error {
	mg.SerialDeps(pythonTestDeps...)
	mg.Deps(devtools.BuildSystemTestBinary)
	return devtools.PythonTest(devtools.DefaultPythonTestUnitArgs())
}

// PythonVirtualEnv creates the testing virtual environment and prints its location.
func PythonVirtualEnv() error {
	venv, err := devtools.PythonVirtualenv(true)
	if err != nil {
		return err
	}
	fmt.Println(venv)
	return nil
}
