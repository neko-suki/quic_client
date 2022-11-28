#!/bin/bash
find -name *.cpp | xargs clang-format -i
find -name *.hpp | xargs clang-format -i