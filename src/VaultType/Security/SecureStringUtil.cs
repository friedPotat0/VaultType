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

    // Same, but without surrounding whitespace. Only for machine-generated values such as an API
    // client secret: those never contain a space, but they are pasted from a password manager or a
    // web page, and a stray one riding along turns a correct secret into an invalid_client refusal
    // the user cannot see. Never use this on a master password - there a space is part of the secret.
    public static unsafe byte[] ToTrimmedUtf8Bytes(SecureString value)
    {
        IntPtr bstr = Marshal.SecureStringToBSTR(value);
        try
        {
            char* chars = (char*)bstr;
            int end = Marshal.ReadInt32(bstr, -4) / 2;
            int start = 0;
            while (start < end && char.IsWhiteSpace(chars[start])) start++;
            while (end > start && char.IsWhiteSpace(chars[end - 1])) end--;

            int charLen = end - start;
            if (charLen == 0) return Array.Empty<byte>();
            int byteLen = Encoding.UTF8.GetByteCount(chars + start, charLen);
            byte[] bytes = new byte[byteLen];
            fixed (byte* b = bytes) Encoding.UTF8.GetBytes(chars + start, charLen, b, byteLen);
            return bytes;
        }
        finally { Marshal.ZeroFreeBSTR(bstr); }
    }
}
