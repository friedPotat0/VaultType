using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace VaultType.Security;

public static class SecureStringUtil
{
    // Marshal a SecureString to a fresh UTF-8 byte array. The caller owns the result and MUST wipe
    // it (CryptographicOperations.ZeroMemory) once done - it holds the plaintext master password.
    public static unsafe byte[] ToUtf8Bytes(SecureString value)
    {
        IntPtr bstr = Marshal.SecureStringToBSTR(value);
        try
        {
            char* chars = (char*)bstr;
            int charLen = Marshal.ReadInt32(bstr, -4) / 2;   // BSTR byte-length prefix / 2 = char count
            int byteLen = Encoding.UTF8.GetByteCount(chars, charLen);
            byte[] bytes = new byte[byteLen];
            fixed (byte* b = bytes) Encoding.UTF8.GetBytes(chars, charLen, b, byteLen);
            return bytes;
        }
        finally { Marshal.ZeroFreeBSTR(bstr); }
    }
}
