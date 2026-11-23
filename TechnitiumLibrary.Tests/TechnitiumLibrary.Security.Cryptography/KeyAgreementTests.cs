using System.Numerics;
using System.Security.Cryptography;
using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class KeyAgreementTests
    {
        [Theory]
        [InlineData(KeyAgreementKeyDerivationHashAlgorithm.SHA256, 32)]
        [InlineData(KeyAgreementKeyDerivationHashAlgorithm.SHA384, 48)]
        [InlineData(KeyAgreementKeyDerivationHashAlgorithm.SHA512, 64)]
        public void HashKeyDerivationProducesExpectedLength(KeyAgreementKeyDerivationHashAlgorithm hashAlgorithm, int expectedLength)
        {
            TestKeyAgreement agreement = new TestKeyAgreement(KeyAgreementKeyDerivationFunction.Hash, hashAlgorithm, [1, 2, 3]);

            byte[] key = agreement.DeriveKeyMaterial([9, 8, 7]);

            Assert.Equal(expectedLength, key.Length);
            Assert.Equal(KeyAgreementKeyDerivationFunction.Hash, agreement.KeyDerivationFunction);
            Assert.Equal(hashAlgorithm, agreement.KeyDerivationHashAlgorithm);
            Assert.Equal([9, 8, 7], agreement.LastOtherPartyPublicKey);
        }

        [Theory]
        [InlineData(KeyAgreementKeyDerivationHashAlgorithm.SHA256, 32)]
        [InlineData(KeyAgreementKeyDerivationHashAlgorithm.SHA384, 48)]
        [InlineData(KeyAgreementKeyDerivationHashAlgorithm.SHA512, 64)]
        public void HmacKeyDerivationProducesExpectedLength(KeyAgreementKeyDerivationHashAlgorithm hashAlgorithm, int expectedLength)
        {
            TestKeyAgreement agreement = new TestKeyAgreement(KeyAgreementKeyDerivationFunction.Hmac, hashAlgorithm, [1, 2, 3])
            {
                HmacKey = [4, 5, 6, 7]
            };

            byte[] key = agreement.DeriveKeyMaterial([9, 8, 7]);

            Assert.Equal(expectedLength, key.Length);
            Assert.Equal([4, 5, 6, 7], agreement.HmacKey);
        }

        [Fact]
        public void UnsupportedKeyDerivationSettingsThrow()
        {
            Assert.Throws<CryptoException>(() => new TestKeyAgreement((KeyAgreementKeyDerivationFunction)99, KeyAgreementKeyDerivationHashAlgorithm.SHA256, [1]).DeriveKeyMaterial([2]));
            Assert.Throws<CryptoException>(() => new TestKeyAgreement(KeyAgreementKeyDerivationFunction.Hash, (KeyAgreementKeyDerivationHashAlgorithm)99, [1]).DeriveKeyMaterial([2]));
            Assert.Throws<CryptoException>(() => new TestKeyAgreement(KeyAgreementKeyDerivationFunction.Hmac, (KeyAgreementKeyDerivationHashAlgorithm)99, [1]) { HmacKey = [1] }.DeriveKeyMaterial([2]));
        }

        [Fact]
        public void DiffieHellmanPublicKeysRoundTripAndDeriveSameSecret()
        {
            BigInteger p = new BigInteger(467);
            BigInteger g = new BigInteger(2);
            DiffieHellmanPublicKey seed = new DiffieHellmanPublicKey(16, p, g, new BigInteger(5));
            DiffieHellman alice = new DiffieHellman(seed, KeyAgreementKeyDerivationFunction.Hash, KeyAgreementKeyDerivationHashAlgorithm.SHA256);
            DiffieHellman bob = new DiffieHellman(seed, KeyAgreementKeyDerivationFunction.Hash, KeyAgreementKeyDerivationHashAlgorithm.SHA256);

            DiffieHellmanPublicKey alicePublic = new DiffieHellmanPublicKey(alice.GetPublicKey());
            DiffieHellmanPublicKey bobPublic = new DiffieHellmanPublicKey(bob.GetPublicKey());

            Assert.Equal(DiffieHellmanGroupType.None, alice.Group);
            Assert.Equal(16, alice.KeySize);
            Assert.Equal(p, alice.P);
            Assert.Equal(g, alice.G);
            Assert.Equal(alicePublic.P, bobPublic.P);
            Assert.Equal(alicePublic.G, bobPublic.G);
            Assert.Equal(alicePublic.KeySize, bobPublic.KeySize);
            Assert.Equal(alice.DeriveKeyMaterial(bob.GetPublicKey()), bob.DeriveKeyMaterial(alice.GetPublicKey()));
        }

        [Fact]
        public void DiffieHellmanGroupsAndInvalidPublicKeysAreValidated()
        {
            DiffieHellmanGroup group = DiffieHellmanGroup.GetGroup(DiffieHellmanGroupType.RFC3526_GROUP14_2048BIT);
            DiffieHellman alice = new DiffieHellman(DiffieHellmanGroupType.RFC3526_GROUP14_2048BIT, KeyAgreementKeyDerivationFunction.Hmac, KeyAgreementKeyDerivationHashAlgorithm.SHA256)
            {
                HmacKey = [1, 2, 3]
            };
            DiffieHellman bob = new DiffieHellman(DiffieHellmanGroupType.RFC3526_GROUP14_2048BIT, KeyAgreementKeyDerivationFunction.Hmac, KeyAgreementKeyDerivationHashAlgorithm.SHA256)
            {
                HmacKey = [1, 2, 3]
            };

            Assert.Equal(2048, group.KeySize);
            Assert.Equal(DiffieHellmanGroupType.RFC3526_GROUP14_2048BIT, group.Group);
            Assert.Equal(new BigInteger(2), group.G);
            Assert.Equal(alice.DeriveKeyMaterial(bob.GetPublicKey()), bob.DeriveKeyMaterial(alice.GetPublicKey()));
            Assert.Throws<CryptoException>(() => DiffieHellmanGroup.GetGroup(DiffieHellmanGroupType.None));
            Assert.Throws<InvalidDataException>(() => new DiffieHellmanPublicKey([0, 1, 2]));
            Assert.Throws<CryptoException>(() => new DiffieHellmanPublicKey(16, new BigInteger(467), new BigInteger(1), new BigInteger(5)));
            Assert.Throws<CryptoException>(() => new DiffieHellmanPublicKey(16, new BigInteger(467), new BigInteger(2), new BigInteger(1)));
            Assert.Throws<CryptoException>(() => alice.DeriveKeyMaterial(new DiffieHellman(DiffieHellmanGroupType.RFC3526_GROUP15_3072BIT, KeyAgreementKeyDerivationFunction.Hmac, KeyAgreementKeyDerivationHashAlgorithm.SHA256) { HmacKey = [1, 2, 3] }.GetPublicKey()));
        }

        [Theory]
        [InlineData(KeyAgreementKeyDerivationHashAlgorithm.SHA256, 32)]
        [InlineData(KeyAgreementKeyDerivationHashAlgorithm.SHA384, 48)]
        [InlineData(KeyAgreementKeyDerivationHashAlgorithm.SHA512, 64)]
        public void ECDiffieHellmanDerivesSameSecretOnSupportedPlatforms(KeyAgreementKeyDerivationHashAlgorithm hashAlgorithm, int expectedLength)
        {
            if (!OperatingSystem.IsWindows())
                return;

            global::TechnitiumLibrary.Security.Cryptography.ECDiffieHellman alice = new global::TechnitiumLibrary.Security.Cryptography.ECDiffieHellman(256, KeyAgreementKeyDerivationFunction.Hash, hashAlgorithm);
            global::TechnitiumLibrary.Security.Cryptography.ECDiffieHellman bob = new global::TechnitiumLibrary.Security.Cryptography.ECDiffieHellman(256, KeyAgreementKeyDerivationFunction.Hash, hashAlgorithm);

            byte[] aliceSecret = alice.DeriveKeyMaterial(bob.GetPublicKey());
            byte[] bobSecret = bob.DeriveKeyMaterial(alice.GetPublicKey());

            Assert.Equal(expectedLength, aliceSecret.Length);
            Assert.Equal(aliceSecret, bobSecret);
        }

        [Fact]
        public void ECDiffieHellmanUnsupportedHashThrowsOnSupportedPlatforms()
        {
            if (!OperatingSystem.IsWindows())
                return;

            Assert.Throws<CryptoException>(() => new global::TechnitiumLibrary.Security.Cryptography.ECDiffieHellman(256, KeyAgreementKeyDerivationFunction.Hash, (KeyAgreementKeyDerivationHashAlgorithm)99));
        }

        private sealed class TestKeyAgreement : KeyAgreement
        {
            private readonly byte[] _computedKey;

            public TestKeyAgreement(KeyAgreementKeyDerivationFunction kdFunc, KeyAgreementKeyDerivationHashAlgorithm kdHashAlgo, byte[] computedKey)
                : base(kdFunc, kdHashAlgo)
            {
                _computedKey = computedKey;
            }

            public byte[]? LastOtherPartyPublicKey { get; private set; }

            public override byte[] GetPublicKey()
            {
                return [1, 2, 3];
            }

            protected override byte[] ComputeKey(byte[] otherPartyPublicKey)
            {
                LastOtherPartyPublicKey = otherPartyPublicKey;
                return _computedKey;
            }
        }
    }
}
