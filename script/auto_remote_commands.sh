#!/usr/bin/expect
set timeout 120
set host [lindex $argv 0]     
set username [lindex $argv 1]
set password [lindex $argv 2]
set port [lindex $argv 3]
set commands [lindex $argv 4]
spawn /usr/bin/ssh  -p $port $username@$host
expect {
"(yes/no)?"
   {
    send "yes\n"
    expect "*assword:" { send "$password\n"}
}
"*assword:"
{
send "$password\n"
}
}
expect "]*"
send "$commands\r"
expect "]*"
send "exit\r"
expect eof
