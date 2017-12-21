#!/usr/bin/env python
import filecmp, optparse, os, re, signal, subprocess, sys

config_file = 'include/mbedtls/config.h'
cc_command = os.getenv('CC', 'cc')
make_command = os.getenv('MAKE', 'make')

restore_config = False
config_backup = config_file + '.bak'
def set_config_full():
    if os.path.exists(config_backup):
        sys.stderr.write("Backup config file found: " + config_backup +
                         ", aborting\n")
        sys.exit(124);
    global restore_config
    restore_config = True
    subprocess.check_call(['perl', 'scripts/config.pl',
                            '--backup', config_backup, 'full'])
def cleanup():
    if restore_config and os.path.exists(config_backup):
        os.rename(config_backup, config_file)

def signalled(signum, frame):
    cleanup()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)

class DependError(Exception):
    def __init__(self, message, clause):
        self.message = message
        self.clause = clause
    def __str__(self):
        return ('Parse error in output of $CC -MM: %s\n%s' %
                (self.message, self.clause))
def massage_clause(clause, full_program):
    # Parse the logical line
    clause = clause.strip()
    if clause == '':
         return clause
    target_rhs = clause.split(':')
    if len(target_rhs) != 2:
        raise DependError('not in the form "TARGET: DEPENDENCIES"', clause)
    target = target_rhs[0]
    dependencies = re.split(r'\s+', target_rhs[1].lstrip())
    if len(dependencies) < 1:
        raise DependError('missing at least one dependency', clause)
    # The first file should be the C source file, which may be in a
    # subdirectory. If it is, amend the target to be in that directory.
    c_source = dependencies[0]
    slash = c_source.rfind('/')
    if slash >= 0:
        target = c_source[:slash+1] + target
    # Add dependencies for the executable if relevant
    targets = [target]
    if full_program:
        targets.append(re.sub(r'\.[^.]*\Z', r'', target) + '$(EXEXT)')
    # Sort and uniquify the headers so that they don't depend on the exact
    # compiler output (some versions of gcc don't uniquify the header list)
    canonicalized_headers = sorted(set(dependencies[1:]))
    # Assemble the massaged clause with canonicalized whitespace
    return (' '.join(targets) + ': ' +
            ' \\\n  '.join([c_source] + canonicalized_headers))

def massage_depend(raw, full_program):
    clauses = re.sub(r'\\\n', r'', raw, len(raw)).split('\n')
    return '\n'.join([massage_clause(clause, full_program)
                      for clause in clauses])

def generate_depend(directory, files, full_program, diff_only):
    raw = subprocess.check_output('cd ' + directory + ' && ' +
                                  cc_command + ' -I ../include -MM ' +
                                  files,
                                  shell=True)
    cooked = massage_depend(raw, full_program)
    depend_file = os.path.join(directory, '.depend')
    depend_new = os.path.join(directory, '.depend.new')
    with open(depend_new, 'w') as out:
        out.write(cooked)
    if diff_only:
        ret = subprocess.call(['diff', depend_file, depend_new])
        os.remove(depend_new)
        if ret > 1:
            raise subprocess.CalledProcessError(ret, 'diff')
        return ret
    elif filecmp.cmp(depend_file, depend_new):
        os.remove(depend_new)
    else:
        os.rename(depend_new, depend_file)
    return 0

def generate_all(diff_only):
    ret = 0
    try:
        set_config_full()
        ret = max(ret, generate_depend('library', '*.c', False, diff_only))
        ret = max(ret, generate_depend('programs', '*/*.c', True, diff_only))
        subprocess.check_call(make_command + ' -C tests all_c', shell=True)
        ret = max(ret, generate_depend('tests', '*.c', True, diff_only))
    finally:
        cleanup()
    return ret

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-n', '--diff-only',
                      action='store_true', dest='diff_only', default=False,
                      help="Don't change .depend, only print a diff of what needs to change")
    (options, args) = parser.parse_args()
    signal.signal(signal.SIGHUP, signalled)
    signal.signal(signal.SIGINT, signalled)
    signal.signal(signal.SIGTERM, signalled)
    sys.exit(generate_all(options.diff_only))
