#!/bin/bash
if [[ -x shit.t ]]
then
    echo "File 'tests' is executable"
else
    echo "File 'tests' is not executable or found"
fi