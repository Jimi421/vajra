#!/usr/bin/expect -f
# brute-tcp-template.sh — generic expect skeleton for menu-driven TCP brute force
#
# Customize the four CAPS PLACEHOLDERS below for your target service.
# Service drops on Incorrect = reconnect per attempt (this template handles that).
#
# Usage:
#   ./brute-tcp-template.sh <ip> <port> <wordlist>
#
# Workflow:
#   1. nc -nv $ip $port manually first
#   2. Note: menu regex, command to send, prompt regex, success/fail strings
#   3. Fill in the four placeholders below
#   4. Run

set timeout 5

# ─── arg parsing ─────────────────────────────────────────────
if {[llength $argv] < 3} {
    puts "Usage: $argv0 <ip_address> <port> <wordlist>"
    exit 1
}
set ip       [lindex $argv 0]
set port     [lindex $argv 1]
set wordlist [lindex $argv 2]

# ─── CUSTOMIZE THESE FOUR ────────────────────────────────────
# Regex matching the menu prompt (what nc shows on connect)
set MENU_RE "MENU_PROMPT_REGEX_HERE"

# Command to send to trigger the answer prompt (e.g. "ANSONE", "LOGIN")
set CMD "COMMAND_TO_SEND"

# Regex matching the answer prompt (what shows after sending CMD)
set ANSWER_RE "ANSWER_PROMPT_REGEX_HERE"

# Regex matching successful response
set SUCCESS_RE "Correct|Access granted|Welcome"
# ─────────────────────────────────────────────────────────────

if {[catch {open $wordlist r} fh]} {
    puts "ERROR: cannot open '$wordlist': $fh"
    exit 1
}

puts "\[*\] Target:    $ip:$port"
puts "\[*\] Wordlist:  $wordlist"
puts "\[*\] Command:   $CMD"
puts "\[*\] Starting..."
puts ""

set attempt 0
while {[gets $fh ans] != -1} {
    set ans [string trim $ans]
    if {$ans eq "" || [string index $ans 0] eq "#"} { continue }

    incr attempt
    puts -nonewline "\[$attempt\] $ans ... "
    flush stdout

    log_user 0
    spawn -noecho nc -nvv $ip $port

    # menu
    expect {
        -re $MENU_RE {}
        timeout { puts "TIMEOUT menu"; catch {close}; wait; continue }
        eof     { puts "EOF menu"; wait; continue }
    }

    send "$CMD\r"

    # answer prompt
    expect {
        -re $ANSWER_RE {}
        timeout { puts "no prompt"; catch {close}; wait; continue }
        eof     { puts "EOF prompt"; wait; continue }
    }

    send "$ans\r"

    # check response
    expect {
        -re $SUCCESS_RE {
            log_user 1
            puts "CORRECT"
            puts ""
            puts "════════════════════════════════════════════════"
            puts "  ✓ Answer = $ans"
            puts "════════════════════════════════════════════════"
            catch {close}
            wait
            close $fh
            exit 0
        }
        -re "Incorrect|Wrong|Invalid|Denied" { puts "incorrect" }
        eof     { puts "EOF" }
        timeout { puts "timeout" }
    }

    catch {close}
    wait
}

puts ""
puts "\[!\] Wordlist exhausted ($attempt attempts), no correct answer."
close $fh
exit 1
