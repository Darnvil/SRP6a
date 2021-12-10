using System.Globalization;
using System.Numerics;
using System.Text;

namespace SRP;

public static class Helpers
{
    public static string RandomBigIntInString(int length)
    {
        var stringBuilder = new StringBuilder();
        var Random = new Random();

        var num = (byte)Random.Next(1, 16);
        stringBuilder.Append(Convert.ToString(num, 16));
        for (var i = 1; i < length * 2; ++i)
        {
            num = (byte)Random.Next(0, 16);
            stringBuilder.Append(Convert.ToString(num, 16));
        }
        
        return stringBuilder.ToString();
    }
    
    public static byte[] ToBytes(this string hex)
    {
        var hexAsBytes = new byte[hex.Length / 2];

        for (var i = 0; i < hex.Length; i += 2)
        {
            hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }

        return hexAsBytes;
    }

    public static BigInteger ToSrpBigInt(this byte[] bytes)
    {
        return new BigInteger(bytes, true, true);
    }

    public static BigInteger ToSrpBigInt(this string hex)
    {
        return BigInteger.Parse("0" + hex, NumberStyles.HexNumber);
    }

    public static byte[] PadBytes(byte[] bytes, int length)
    {
        var padded = new byte[length];
        Array.Copy(bytes, 0, padded, length - bytes.Length, bytes.Length);

        return padded;
    }
    
    public static BigInteger ComputeK(int g, BigInteger N, Func<byte[], byte[]> H)
    {
        var NToBytes = N.ToByteArray(true, true);
        var gBytes = PadBytes(BitConverter.GetBytes(g).Reverse().ToArray(), NToBytes.Length);

        var k = H(NToBytes.Concat(gBytes).ToArray());

        return new BigInteger(k, isBigEndian: true);
    }

    public static BigInteger ComputeU(Func<byte[], byte[]> H, BigInteger A, BigInteger B)
    {
        return H(A.ToByteArray(true, true)
            .Concat(B.ToByteArray(true, true))
            .ToArray())
            .ToSrpBigInt();
    }

    public static BigInteger ComputeClientProof(BigInteger N, Func<byte[], byte[]> H, BigInteger A, BigInteger B,
        BigInteger S)
    {
        var padLength = N.ToByteArray(true, true).Length;

        return H((PadBytes(A.ToByteArray(true, true), padLength))
            .Concat(PadBytes(B.ToByteArray(true, true), padLength))
            .Concat(PadBytes(S.ToByteArray(true, true), padLength))
            .ToArray())
            .ToSrpBigInt();
    }

    public static BigInteger ComputeServerProof(BigInteger N, Func<byte[], byte[]> H, BigInteger A, BigInteger M1,
        BigInteger S)
    {
        var padLength = N.ToByteArray(true, true).Length;

        // M2 = H( A | M1 | S )
        return H((PadBytes(A.ToByteArray(true, true), padLength))
                .Concat(PadBytes(M1.ToByteArray(true, true), padLength))
                .Concat(PadBytes(S.ToByteArray(true, true), padLength))
                .ToArray())
            .ToSrpBigInt();
    }

    public static void Log(string header, string value)
    {
        Console.WriteLine(header + ": " + value);
    }
}