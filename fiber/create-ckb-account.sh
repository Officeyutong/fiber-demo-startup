#!/usr/bin/expect

spawn /ckb-cli account new
expect "Password:"
send "12345678\r"
expect "Repeat password:"
send "12345678\r"
expect eof
