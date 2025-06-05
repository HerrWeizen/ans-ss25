#!/usr/bin/env bash

vagrant up
fish -- bash -c "vagrant ssh; exec bash"
fish -- bash -c "vagrant ssh; exec bash"
