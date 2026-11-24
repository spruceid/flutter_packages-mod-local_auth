// Copyright 2013 The Flutter Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import LocalAuthentication

#if os(macOS)
  import Cocoa
  import FlutterMacOS
#elseif os(iOS)
  import Flutter
  import UIKit
#endif

/// A default context factory that wraps standard LAContext allocation.
final class DefaultAuthContextFactory: AuthContextFactory {
  func createAuthContext() -> AuthContext {
    return LAContext()
  }
}

// MARK: -

/// A data container for sticky auth state.
struct StickyAuthState {
  let options: AuthOptions
  let strings: AuthStrings
  let resultHandler: (Result<AuthResultDetails, Error>) -> Void
}

// MARK: -

/// A flutter plugin for local authentication.
// TODO(stuartmorgan): Remove the @unchecked Sendable, and convert to strict thread enforcement.
// This was added to minimize the changes while converting from Swift to Objective-C.
public final class LocalAuthPlugin: NSObject, FlutterPlugin, LocalAuthApi, @unchecked Sendable {

  /// The factory to create LAContexts.
  private let authContextFactory: AuthContextFactory
  /// Manages the last call state for sticky auth.
  private var lastCallState: StickyAuthState?

  public static func register(with registrar: FlutterPluginRegistrar) {
    let instance = LocalAuthPlugin(
      contextFactory: DefaultAuthContextFactory())
    // Register for both application and scene delegates for backward compatibility.
    // Apps using UIScene lifecycle will receive sceneDidBecomeActive,
    // while apps not yet migrated will receive applicationDidBecomeActive.
    registrar.addApplicationDelegate(instance)
    #if os(iOS)
      registrar.addSceneDelegate(instance)
    #endif
    // Workaround for https://github.com/flutter/flutter/issues/118103.
    #if os(iOS)
      let messenger = registrar.messenger()
    #else
      let messenger = registrar.messenger
    #endif
    LocalAuthApiSetup.setUp(binaryMessenger: messenger, api: instance)
  }

  /// Returns an instance that uses the given factory to create LAContexts.
  init(
    contextFactory: AuthContextFactory
  ) {
    self.authContextFactory = contextFactory
  }

  // MARK: LocalAuthApi

  func clearBiometricChecking() throws {
    // Remove both the keychain baseline and any legacy UserDefaults value, so
    // the next successful biometric auth records a fresh baseline.
    // Never throws: callers use this on paths (e.g. after a passed
    // rechallenge) where an error must not block the rest of the flow.
    let status = deleteKeychainBaseline()
    UserDefaults.standard.removeObject(forKey: BIOMETRIC_CHECK_KEY)
    if status != errSecSuccess && status != errSecItemNotFound {
      NSLog("local_auth: failed to delete biometric baseline from keychain (OSStatus %d)", status)
    }
  }

  func migrateLegacyBiometricBaseline(trusted: Bool) throws -> String {
    // Only acts when the keychain has no baseline yet and an older build left
    // one in UserDefaults. UserDefaults is copied to new devices by backups and
    // Quick Start, so the legacy value is only carried over when the app says
    // this device has run the app before (`trusted`); otherwise it is dropped.
    //
    // Returns what happened, for the app's logs: "noLegacyValue",
    // "keychainAlreadySet", "moved" or "discarded".
    guard let legacy = UserDefaults.standard.string(forKey: BIOMETRIC_CHECK_KEY) else {
      return "noLegacyValue"
    }
    switch readKeychainBaseline() {
    case .found:
      // Keychain already authoritative. Drop the stale legacy copy.
      UserDefaults.standard.removeObject(forKey: BIOMETRIC_CHECK_KEY)
      return "keychainAlreadySet"
    case .notFound:
      // Remove the legacy value whatever happens below; it is never compared
      // against directly.
      UserDefaults.standard.removeObject(forKey: BIOMETRIC_CHECK_KEY)
      if trusted {
        let status = writeKeychainBaseline(legacy)
        if status != errSecSuccess {
          // The next successful auth records a fresh baseline instead.
          throw PigeonError(
            code: "keychain_error",
            message: "Failed to move legacy biometric baseline into keychain",
            details: "OSStatus \(status)")
        }
        return "moved"
      }
      return "discarded"
    case .error(let status):
      // Leave everything as is; compareBiometricState fails safe on read errors.
      throw PigeonError(
        code: "keychain_error",
        message: "Failed to read biometric baseline from keychain",
        details: "OSStatus \(status)")
    }
  }

  /// Key used for the legacy UserDefaults value and the keychain account.
  private let BIOMETRIC_CHECK_KEY = "check-biometrics"

  /// Keychain service for the biometric baseline item.
  private let BIOMETRIC_CHECK_SERVICE = "io.flutter.plugins.localauth.biometric-check"

  private enum KeychainRead {
    case found(String)
    case notFound
    case error(OSStatus)
  }

  /// Base query for the baseline item. Deliberately not synchronizable, so
  /// iCloud Keychain never copies it to another device.
  private func keychainBaseQuery() -> [CFString: Any] {
    return [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: BIOMETRIC_CHECK_SERVICE,
      kSecAttrAccount: BIOMETRIC_CHECK_KEY,
    ]
  }

  private func readKeychainBaseline() -> KeychainRead {
    var query = keychainBaseQuery()
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne
    var ref: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &ref)
    if status == errSecItemNotFound {
      return .notFound
    }
    guard status == errSecSuccess else {
      return .error(status)
    }
    guard let data = ref as? Data, let value = String(data: data, encoding: .utf8) else {
      return .error(errSecDecode)
    }
    return .found(value)
  }

  private func writeKeychainBaseline(_ value: String) -> OSStatus {
    let data = Data(value.utf8)
    var addQuery = keychainBaseQuery()
    addQuery[kSecValueData] = data
    // Readable after the first unlock since boot, never migrated to another
    // device, and (unlike WhenPasscodeSet*) not deleted if the passcode is
    // removed — passcode removal resets Face ID / Touch ID, and that reset
    // must still be detected.
    addQuery[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let status = SecItemAdd(addQuery as CFDictionary, nil)
    if status == errSecDuplicateItem {
      let update: [CFString: Any] = [kSecValueData: data]
      return SecItemUpdate(keychainBaseQuery() as CFDictionary, update as CFDictionary)
    }
    return status
  }

  @discardableResult
  private func deleteKeychainBaseline() -> OSStatus {
    return SecItemDelete(keychainBaseQuery() as CFDictionary)
  }

  private func base64UrlSafe(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private func getBiometricState() -> String? {
    let context = LAContext()
    var error: NSError?
    context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    guard error == nil else { return nil }
    guard let domainState = context.evaluatedPolicyDomainState else { return nil }
    return base64UrlSafe(domainState)
  }

  /// Returns true if the enrolled biometrics match the stored baseline.
  ///
  /// The baseline lives in the keychain (device-only). A missing baseline is
  /// trust-on-first-use: the current state is recorded and treated as valid.
  /// Any keychain read failure other than "not found" returns false, so a
  /// keychain problem can never silently overwrite the baseline and hide a
  /// biometric change.
  private func compareBiometricState() -> Bool {
    guard let current = getBiometricState() else {
      return false
    }

    // Never compare against a legacy UserDefaults value: it may have been
    // restored from another device. The app normally removes it through
    // migrateLegacyBiometricBaseline before authenticating.
    if UserDefaults.standard.object(forKey: BIOMETRIC_CHECK_KEY) != nil {
      UserDefaults.standard.removeObject(forKey: BIOMETRIC_CHECK_KEY)
    }

    switch readKeychainBaseline() {
    case .found(let previous):
      return current == previous
    case .notFound:
      let status = writeKeychainBaseline(current)
      if status != errSecSuccess {
        NSLog("local_auth: failed to store biometric baseline in keychain (OSStatus %d)", status)
      }
      return true
    case .error(let status):
      NSLog("local_auth: failed to read biometric baseline from keychain (OSStatus %d)", status)
      return false
    }
  }

  func authenticate(
    options: AuthOptions,
    strings: AuthStrings,
    completion: @escaping (Result<AuthResultDetails, Error>) -> Void
  ) {
    var context = authContextFactory.createAuthContext()
    lastCallState = nil
    context.localizedFallbackTitle = strings.localizedFallbackTitle

    let policy =
      options.biometricOnly
      ? LAPolicy.deviceOwnerAuthenticationWithBiometrics
      : LAPolicy.deviceOwnerAuthentication
    var authError: NSError?
    if context.canEvaluatePolicy(policy, error: &authError) {
      context.evaluatePolicy(
        policy,
        localizedReason: strings.reason
      ) { [weak self] (success: Bool, error: Error?) in
        DispatchQueue.main.async {
          self?.handleAuthReply(
            success: success,
            error: error,
            options: options,
            strings: strings,
            completion: completion)
        }
      }
    } else {
      if let authError = authError {
        self.handleError(authError, options: options, strings: strings, completion: completion)
      } else {
        // This should not happen according to docs, but if it ever does the plugin should still
        // fire the completion.
        completion(
          .success(
            AuthResultDetails(
              result: .unknownError,
              errorMessage: "canEvaluatePolicy failed without an error"
            )))
      }
    }
  }

  func deviceCanSupportBiometrics() throws -> Bool {
    let context = authContextFactory.createAuthContext()
    var authError: NSError?
    // Check if authentication with biometrics is possible.
    if context.canEvaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      error: &authError)
    {
      if authError == nil {
        return true
      }
    }
    // If not, check if it is because no biometrics are enrolled (but still present).
    if let authError = authError {
      if authError.code == LAError.biometryNotEnrolled.rawValue {
        return true
      }
      // Biometry hardware is available, but possibly permissions were denied.
      if authError.code == LAError.biometryNotAvailable.rawValue
        && context.biometryType != LABiometryType.none
      {
        return true
      }
    }

    return false
  }

  func getEnrolledBiometrics() throws -> [AuthBiometric] {
    let context = authContextFactory.createAuthContext()
    var biometrics: [AuthBiometric] = []
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
      if context.biometryType == LABiometryType.faceID {
        biometrics.append(AuthBiometric.face)
      }
      if context.biometryType == LABiometryType.touchID {
        biometrics.append(AuthBiometric.fingerprint)
      }
    }
    return biometrics
  }

  func getHardwareBiometricCapabilities() throws -> [AuthBiometric] {
    let context = authContextFactory.createAuthContext()
    var error: NSError?
    _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    switch context.biometryType {
    case .faceID:
      return [AuthBiometric.face]
    case .touchID:
      return [AuthBiometric.fingerprint]
    default:
      return []
    }
  }

  func isDeviceSupported() throws -> Bool {
    let context = authContextFactory.createAuthContext()
    return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
  }

  // MARK: Private Methods

  private func handleAuthReply(
    success: Bool,
    error: Error?,
    options: AuthOptions,
    strings: AuthStrings,
    completion: @escaping (Result<AuthResultDetails, Error>) -> Void
  ) {
    if success {
        if options.checkBiometricInvalidationForKey {
            let res = compareBiometricState() ? AuthResult.successValidated : AuthResult.successInvalidated
            handleResult(result: res, completion: completion)
        } else {
            handleResult(result: .success, completion: completion)
        }
        return
    }

    if let error = error as? NSError {
      if error.code == LAError.Code.systemCancel.rawValue && options.sticky {
        lastCallState = StickyAuthState(
          options: options,
          strings: strings,
          resultHandler: completion)
      } else {
        handleError(error, options: options, strings: strings, completion: completion)
      }
    } else {
      // This should not happen according to docs, but if it ever does the plugin should still
      // fire the completion.
      completion(
        .success(
          AuthResultDetails(
            result: .unknownError,
            errorMessage: "evaluatePolicy failed without an error"
          )))
    }
  }
    
  private func handleResult(
    result: AuthResult, completion: @escaping (Result<AuthResultDetails, Error>) -> Void
  ) {
    completion(
      .success(
        AuthResultDetails(
          result: result,
          errorMessage: nil,
          errorDetails: nil)
      ))
  }

  private func handleError(
    _ authError: NSError,
    options: AuthOptions,
    strings: AuthStrings,
    completion: @escaping (Result<AuthResultDetails, Error>) -> Void
  ) {
    let result: AuthResult
    let errorCode = LAError.Code(rawValue: authError.code)
    switch errorCode {
    case .appCancel:
      result = .appCancel
    case .systemCancel:
      result = .systemCancel
    case .userCancel:
      result = .userCancel
    case .biometryDisconnected:
      result = .biometryDisconnected
    case .biometryLockout:
      result = .biometryLockout
    case .biometryNotAvailable:
      result = .biometryNotAvailable
    case .biometryNotEnrolled:
      result = .biometryNotEnrolled
    case .biometryNotPaired:
      result = .biometryNotPaired
    case .authenticationFailed:
      result = .authenticationFailed
    case .invalidContext:
      result = .invalidContext
    case .invalidDimensions:
      result = .invalidDimensions
    case .notInteractive:
      result = .notInteractive
    case .passcodeNotSet:
      result = .passcodeNotSet
    case .userFallback:
      result = .userFallback
    default:
      result = .unknownError
    }
    completion(
      .success(
        AuthResultDetails(
          result: result,
          errorMessage: authError.localizedDescription,
          errorDetails: "\(authError.domain): \(authError.code)")
      ))
  }

  private func retryStickyAuth() {
    if let lastCallState = self.lastCallState {
      authenticate(
        options: lastCallState.options,
        strings: lastCallState.strings,
        completion: lastCallState.resultHandler)
    }
  }

  // MARK: App delegate

  // These methods are called when the app is resumed from the background only on iOS.
  // Both are kept for backward compatibility: sceneDidBecomeActive for apps using UIScene lifecycle,
  // and applicationDidBecomeActive for apps that haven't migrated yet.
  #if os(iOS)
    @MainActor
    public func sceneDidBecomeActive(_ scene: UIScene) {
      retryStickyAuth()
    }

    @MainActor
    public func applicationDidBecomeActive(_ application: UIApplication) {
      retryStickyAuth()
    }
  #endif  // os(iOS)

}

// MARK: - FlutterSceneLifeCycleDelegate

#if os(iOS)
  extension LocalAuthPlugin: FlutterSceneLifeCycleDelegate {}
#endif
