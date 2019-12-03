#!/bin/bash


openssl s_server -CAfile ca.pem -cert server.pem -key server.key -Verify 1


