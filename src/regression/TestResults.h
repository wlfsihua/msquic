/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include <vector>
#include <string>
#include <memory>

class TestResult {
public:
    std::string FolderName;
    virtual std::string GetTestResultForPrinting() const = 0;
};

extern std::vector<std::shared_ptr<TestResult>> TestResults;
