import 'dart:convert';

import 'package:encrypt/encrypt.dart';

class EncryptionService {
  static const _defaultTimeOffset = 1000 * 30 * 60; // 30 minutes
  final String _secret;
  final int timeOffset;

  /// The [timeOffset] is the minimum expire time in milliseconds
  EncryptionService(this._secret, {this.timeOffset = _defaultTimeOffset});

  /// Returns the encrypted text together with the time it will expire
  EncryptedData encrypt(String text) {
    final now = DateTime.now().millisecondsSinceEpoch ~/ timeOffset;
    final iv = IV.fromUtf8(now.toString());
    final encrypter = Encrypter(AES(Key.fromUtf8(_secret)));
    final encrypted = encrypter.encrypt(text, iv: iv);
    return EncryptedData(encrypted.base64, DateTime.fromMillisecondsSinceEpoch((now + 2) * timeOffset));
  }

  String? _decrypt(String text, int time) {
    final encrypter = Encrypter(AES(Key.fromUtf8(_secret)));
    final encrypted = Encrypted(base64.decode(text));
    try {
      final iv = IV.fromUtf8(time.toString());
      return encrypter.decrypt(encrypted, iv: iv);
    } catch (_) {
      return null;
    }
  }

  /// Returns the decrypted text if it is not expired
  /// The [timeOffset] is the minimum expire time in milliseconds and must be the same as when encrypting
  String? decrypt(String text) {
    final now = DateTime.now().millisecondsSinceEpoch ~/ timeOffset;
    return _decrypt(text, now) ?? _decrypt(text, now - 1);
  }
}

class EncryptedData {
  final String data;
  final DateTime expireTime;

  EncryptedData(this.data, this.expireTime);
}
