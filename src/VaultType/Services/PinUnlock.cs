using VaultType.Vault;

namespace VaultType.Services;

// Thin facade over the backend's PIN envelope for the app's unlock flow.
public static class PinUnlock
{
    public static bool Available(VaultSession s) => s.Backend.PinAvailable;

    // Enroll after a successful sign-in (session unlocked). Wipes pin.
    public static void Enroll(VaultSession s, byte[] pin)
        => s.Backend.EnrollPin(pin, s.Cfg.PinRequireMasterOnRestart);

    public static Task<UnlockStatus> Unlock(VaultSession s, byte[] pin)
        => s.Backend.UnlockWithPinAsync(pin);

    public static void Remove(VaultSession s) => s.Backend.RemovePin();
}
