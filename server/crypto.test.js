import test from "node:test";
import assert from "node:assert/strict";
import sodium from "libsodium-wrappers-sumo";

test("crypto_box round trip, signature verification, and tamper rejection", async () => {
  await sodium.ready;
  const aliceBox = sodium.crypto_box_keypair();
  const bobBox = sodium.crypto_box_keypair();
  const aliceSign = sodium.crypto_sign_keypair();
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const plaintext = sodium.from_string("CIA demo message");
  const ciphertext = sodium.crypto_box_easy(plaintext, nonce, bobBox.publicKey, aliceBox.privateKey);
  const signature = sodium.crypto_sign_detached(ciphertext, aliceSign.privateKey);

  assert.equal(
    sodium.to_string(sodium.crypto_box_open_easy(ciphertext, nonce, aliceBox.publicKey, bobBox.privateKey)),
    "CIA demo message"
  );
  assert.equal(sodium.crypto_sign_verify_detached(signature, ciphertext, aliceSign.publicKey), true);

  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 1;
  assert.equal(sodium.crypto_sign_verify_detached(signature, tampered, aliceSign.publicKey), false);
  assert.throws(() => sodium.crypto_box_open_easy(tampered, nonce, aliceBox.publicKey, bobBox.privateKey));
});
