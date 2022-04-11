package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Generator for PBE derived keys and ivs as defined by PKCS 12 V1.0.
 * <p>
 * The document this implementation is based on can be found at
 * <a href=https://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html>
 * RSA's PKCS12 Page</a>
 */
public class PKCS12ParametersGenerator
    extends PBEParametersGenerator
{
    public static final int KEY_MATERIAL = 1;
    public static final int IV_MATERIAL  = 2;
    public static final int MAC_MATERIAL = 3;

    private Digest digest;

    private int     u;
    private int     v;

    /**
     * Construct a PKCS 12 Parameters generator. This constructor will
     * accept any digest which also implements ExtendedDigest.
     *
     * @param digest the digest to be used as the source of derived keys.
     * @exception IllegalArgumentException if an unknown digest is passed in.
     */
    public PKCS12ParametersGenerator(
        Digest  digest)
    {
        this.digest = digest;
        if (digest instanceof ExtendedDigest)
        {
            u = digest.getDigestSize();
            v = ((ExtendedDigest)digest).getByteLength();
        }
        else
        {
            throw new IllegalArgumentException("Digest " + digest.getAlgorithmName() + " unsupported");
        }
    }

    /**
     * add a + b + 1, returning the result in a. The a value is treated
     * as a BigInteger of length (b.length * 8) bits. The result is 
     * modulo 2^b.length in case of overflow.
     */
    private void adjust(
        byte[]  a,
        int     aOff,
        byte[]  b)
    {
        int  x = (b[b.length - 1] & 0xff) + (a[aOff + b.length - 1] & 0xff) + 1;

        a[aOff + b.length - 1] = (byte)x;
        x >>>= 8;

        for (int i = b.length - 2; i >= 0; i--)
        {
            x += (b[i] & 0xff) + (a[aOff + i] & 0xff);
            a[aOff + i] = (byte)x;
            x >>>= 8;
        }
    }

    /**
     * generation of a derived key ala PKCS12 V1.0.
     *
     * This implementation seems to match the one in golang:
     * https://github.com/golang/crypto/blob/master/pkcs12/pbkdf.go
     * 
     * 
     */
    private byte[] generateDerivedKey(
        int idByte,
        int n)
    {
        //    1.  Construct a string, D (the "diversifier"), by concatenating v/8
	    //        copies of ID.
        //
        // (v is the length of the internal buffer of the hash function, in bits)
        byte[]  D = new byte[v];

        // n is the length of the output, in bits
        byte[]  dKey = new byte[n];

        //    The following procedure can be used to produce pseudorandom bits for
        //    a particular "purpose" that is identified by a byte called "ID".
        //    This standard specifies 3 different values for the ID byte:

        //    1.  If ID=1, then the pseudorandom bits being produced are to be used
        //        as key material for performing encryption or decryption.

        //    2.  If ID=2, then the pseudorandom bits being produced are to be used
        //        as an IV (Initial Value) for encryption or decryption.

        //    3.  If ID=3, then the pseudorandom bits being produced are to be used
        //        as an integrity key for MACing.

        //    1.  Construct a string, D (the "diversifier"), by concatenating v/8
        //        copies of ID.
        for (int i = 0; i != D.length; i++)
        {
            D[i] = (byte)idByte;
        }

        //    2.  Concatenate copies of the salt together to create a string S of
        //        length v(ceiling(s/v)) bits (the final copy of the salt may be
        //        truncated to create S).  Note that if the salt is the empty
        //        string, then so is S.
        byte[]  S;

        if ((salt != null) && (salt.length != 0))
        {
            S = new byte[v * ((salt.length + v - 1) / v)];

            for (int i = 0; i != S.length; i++)
            {
                S[i] = salt[i % salt.length];
            }
        }
        else
        {
            S = new byte[0];
        }

        //    3.  Concatenate copies of the password together to create a string P
        //        of length v(ceiling(p/v)) bits (the final copy of the password
        //        may be truncated to create P).  Note that if the password is the
        //        empty string, then so is P.
        byte[]  P;

        if ((password != null) && (password.length != 0))
        {
            P = new byte[v * ((password.length + v - 1) / v)];

            for (int i = 0; i != P.length; i++)
            {
                P[i] = password[i % password.length];
            }
        }
        else
        {
            P = new byte[0];
        }


        //    4.  Set I=S||P to be the concatenation of S and P.
        byte[]  I = new byte[S.length + P.length];

        System.arraycopy(S, 0, I, 0, S.length);
        System.arraycopy(P, 0, I, S.length, P.length);

        byte[]  B = new byte[v];
        int     c = (n + u - 1) / u;
        
        //    7.  Concatenate A_1, A_2, ..., A_c together to form a pseudorandom
        //        bit string, A.
        byte[]  A = new byte[u];

        //    6.  For i=1, 2, ..., c, do the following:
        for (int i = 1; i <= c; i++)
        {
            //        A.  Set A2=H^r(D||I). (i.e., the r-th hash of D||1,
		    //            H(H(H(... H(D||I))))
            digest.update(D, 0, D.length);
            digest.update(I, 0, I.length);
            digest.doFinal(A, 0);
            for (int j = 1; j < iterationCount; j++)
            {
                digest.update(A, 0, A.length);
                digest.doFinal(A, 0);
            }

            // B.  Concatenate copies of Ai to create a string B of length v
			//     bits (the final copy of Ai may be truncated to create B)
            for (int j = 0; j != B.length; j++)
            {
                B[j] = A[j % A.length];
            }

            // C.  Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
			//     blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by
			//     setting I_j=(I_j+B+1) mod 2^v for each j.
            for (int j = 0; j != I.length / v; j++)
            {
                adjust(I, j * v, B);
            }

            //    8.  Use the first n bits of A as the output of this entire process.
            if (i == c)
            {
                System.arraycopy(A, 0, dKey, (i - 1) * u, dKey.length - ((i - 1) * u));
            }
            else
            {
                System.arraycopy(A, 0, dKey, (i - 1) * u, A.length);
            }
        }

        return dKey;
    }

    /**
     * Generate a key parameter derived from the password, salt, and iteration
     * count we are currently initialised with.
     *
     * @param keySize the size of the key we want (in bits)
     * @return a KeyParameter object.
     */
    public CipherParameters generateDerivedParameters(
        int keySize)
    {
        keySize = keySize / 8;

        byte[]  dKey = generateDerivedKey(KEY_MATERIAL, keySize);

        return new KeyParameter(dKey, 0, keySize);
    }

    /**
     * Generate a key with initialisation vector parameter derived from
     * the password, salt, and iteration count we are currently initialised
     * with.
     *
     * @param keySize the size of the key we want (in bits)
     * @param ivSize the size of the iv we want (in bits)
     * @return a ParametersWithIV object.
     */
    public CipherParameters generateDerivedParameters(
        int     keySize,
        int     ivSize)
    {
        keySize = keySize / 8;
        ivSize = ivSize / 8;

        byte[]  dKey = generateDerivedKey(KEY_MATERIAL, keySize);

        byte[]  iv = generateDerivedKey(IV_MATERIAL, ivSize);

        return new ParametersWithIV(new KeyParameter(dKey, 0, keySize), iv, 0, ivSize);
    }

    /**
     * Generate a key parameter for use with a MAC derived from the password,
     * salt, and iteration count we are currently initialised with.
     *
     * @param keySize the size of the key we want (in bits)
     * @return a KeyParameter object.
     */
    public CipherParameters generateDerivedMacParameters(
        int keySize)
    {
        keySize = keySize / 8;

        byte[]  dKey = generateDerivedKey(MAC_MATERIAL, keySize);

        return new KeyParameter(dKey, 0, keySize);
    }
}
