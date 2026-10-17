using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

// Level 0 returns SIDs only: never translate members through domain/DNS lookups.
public static class MetakampoLocalSam {
    [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string server, string group, int level,
        out IntPtr buffer, uint maxLength, out uint read, out uint total, ref UIntPtr resume);
    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
    public static string[] MemberSids(string group) {
        var result = new List<string>();
        UIntPtr resume = UIntPtr.Zero;
        int status;
        int pages = 0;
        do {
            IntPtr buffer = IntPtr.Zero;
            uint read, total;
            try {
                status = NetLocalGroupGetMembers(null, group, 0, out buffer, uint.MaxValue,
                    out read, out total, ref resume);
                if (status != 0 && status != 234) throw new Win32Exception(status);
                if (read > 100000 || ++pages > 128 || (status == 234 && read == 0))
                    throw new InvalidOperationException("Local group enumeration did not progress");
                for (int i=0; i<(int)read; i++) {
                    IntPtr sid = Marshal.ReadIntPtr(buffer, checked(i * IntPtr.Size));
                    result.Add(new SecurityIdentifier(sid).Value);
                }
            } finally {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
        } while (status == 234);
        return result.ToArray();
    }
}
