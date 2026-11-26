import pathlib
import re
import sys

def fix_rules_c(s: str) -> str:
    s = s.replace('selinux_state.policy', 'selinux_policy_414_ptr')
    s = s.replace('selinux_state.policy_mutex', 'selinux_policy_414_lock')
    s = s.replace('selinux_state.avc', 'NULL')
    s = s.replace('selinux_state.enforcing', 'selinux_enforcing')

    s = re.sub(
        r'rcu_dereference_protected\s*\(\s*selinux_policy_414_ptr\s*,[^)]*\)',
        'rcu_dereference_protected(selinux_policy_414_ptr, lockdep_is_held(&selinux_policy_414_lock))',
        s,
    )
    s = re.sub(
        r'rcu_assign_pointer\s*\(\s*selinux_policy_414_ptr\s*,',
        'rcu_assign_pointer(selinux_policy_414_ptr,',
        s,
    )
    s = re.sub(
        r'selinux_status_update_policyload\s*\(\s*&selinux_state\s*,\s*([^)]+)\)',
        r'selinux_status_update_policyload(\1)',
        s,
    )
    s = re.sub(
        r'mutex_lock\s*\(\s*&selinux_policy_414_lock\s*\)\s*;',
        'mutex_lock(&selinux_policy_414_lock);',
        s,
    )
    s = re.sub(
        r'mutex_unlock\s*\(\s*&selinux_policy_414_lock\s*\)\s*;',
        'mutex_unlock(&selinux_policy_414_lock);',
        s,
    )

    s = re.sub(r'\bselinux_state\b', 'selinux_enforcing', s)

    s = re.sub(r'\bstruct\s+selinux_policy\s*\*', 'struct policydb *', s)
    s = re.sub(r'->policydb\b', '', s)
    s = re.sub(r'->sidtab\b', '', s)
    s = re.sub(r'->latest_granting\b', '', s)

    header_414 = (
        '#include <linux/rcupdate.h>\n'
        '#include <linux/mutex.h>\n'
        'extern int selinux_enforcing;\n'
        'struct policydb;\n'
        'static struct policydb *selinux_policy_414_ptr = NULL;\n'
        'static DEFINE_MUTEX(selinux_policy_414_lock);\n'
    )
    if 'selinux_policy_414_ptr' not in s:
        s = header_414 + s

    return s

if __name__ == '__main__':
    target = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu/selinux/rules.c')
    text = target.read_text(encoding='utf-8', errors='ignore')
    target.write_text(fix_rules_c(text), encoding='utf-8')
    print(f'Patched: {target}')
