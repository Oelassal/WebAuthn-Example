export class BiometricAuthService {

  constructor(
    private commonCacheService: CommonCacheService,
  ) {}

  // ==========================
  //   PUBLIC API
  // ==========================

  async registerAuthentication(): Promise<"success" | "otp" | "bioFailure"> {
    if (!(await this.isWebAuthnSupported())) {
      return 'otp';
    }

    const isMobile = this.isMobileDevice();
    const biometricAvailable = await this.isBiometricAvailable();

    if (!biometricAvailable) {
      return 'otp';
    }

    try {
      const credential = await this.performBiometricAuthentication();
      if (credential) {
        if (isMobile) {
          localStorage.setItem('authenticationCredentialId', JSON.stringify(credential.id));
        }
        return 'success';
      }
      throw new Error('Biometric credential is null');
    } catch (error) {
      return isMobile ? 'bioFailure' : 'otp';
    }
  }

  // ==========================
  //   BIOMETRIC AUTHENTICATION
  // ==========================

  private async performBiometricAuthentication(): Promise<PublicKeyCredential | null> {
    const publicKey: PublicKeyCredentialCreationOptions = {
      challenge: this.generateChallenge(),
      rp: {
        name: 'Vodafone',
        id: window.location.hostname,
      },
      user: {
        id: new Uint8Array(16),
        name: this.commonCacheService.getPrimaryMsisdn(),
        displayName: '',
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },
        { alg: -257, type: 'public-key' },
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        requireResidentKey: false,
        userVerification: 'required',
      },
      timeout: 60000,
    };

    return navigator.credentials.create({ publicKey }) as Promise<PublicKeyCredential | null>;
  }

  // ==========================
  //   FALLBACK AUTH (PIN/PWD)
  // ==========================

  private async requestPinPasswordBeforeOtp(): Promise<boolean> {
    try {
      return await this.performDevicePinPasswordAuthentication();
    } catch {
      return false;
    }
  }

  private async performDevicePinPasswordAuthentication(): Promise<boolean> {
    const publicKey: PublicKeyCredentialRequestOptions = {
      challenge: this.generateChallenge(),
      rpId: window.location.hostname,
      allowCredentials: [{
        type: 'public-key',
        id: new Uint8Array(16),
      }],
      userVerification: 'required',
      timeout: 60000,
    };

    try {
      const credential = await navigator.credentials.get({ publicKey }) as PublicKeyCredential;
      return !!credential;
    } catch {
      return false;
    }
  }

  // ==========================
  //   ENVIRONMENT CHECKS
  // ==========================

  private isMobileDevice(): boolean {
    const userAgent = navigator.userAgent || navigator.vendor || (window as any).opera;
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|Windows Phone/i.test(userAgent);
  }

  private async isWebAuthnSupported(): Promise<boolean> {
    return !!window.PublicKeyCredential;
  }

  private async isBiometricAvailable(): Promise<boolean> {
    return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  }

  // ==========================
  //   UTILITIES
  // ==========================

  private generateChallenge(): Uint8Array {
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    return challenge;
  }
}