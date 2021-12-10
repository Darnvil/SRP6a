using System.Numerics;

namespace SRP;

public class SrpServer
{
    class User
    {
        public string login;
        public BigInteger verificator;
        public byte[] salt;

        public User(string I, BigInteger v, byte[] s)
        {
            this.login = I;
            this.verificator = v;
            this.salt = s;
        }
    }

    private List<User> users;
    private User currentUser;
    
    private readonly Func<byte[], byte[]> Hash;
    private readonly int generator;
    private readonly BigInteger BigN;

    private BigInteger b;
    public BigInteger B, ClientA;
    public SrpServer(Func<byte[], byte[]> H, int g, BigInteger N)
    {
        this.Hash = H;
        this.generator = g;
        this.BigN = N;

        users = new List<User>();
    }

    public void RegisterNewUser(string I, BigInteger v, byte[] salt)
    {
        var newUser = new User(I, v, salt);
        users.Add(newUser);
    }

    public BigInteger LoginStep1(string I, BigInteger A, SrpClient client)
    {
        if (A.IsZero) throw new Exception("A is equal to zero");
        ClientA = A;
        var index = FindUserIndex(I);
        
        if (index < 0)
        {
            throw new Exception("Cant find login in 'db'");
        }
        currentUser = users[index];

        GenerateB(currentUser.verificator);
        
        client.SetSalt(currentUser.salt);

        return B;
    }

    public BigInteger LoginStep2(BigInteger M1)
    {
        var S = ComputeSessionKey(currentUser.verificator, ClientA);
        Helpers.Log("serverS", S.ToString());

        
        if (!ValidateClientProof(M1, ClientA, S))
            throw new Exception(
                "Can't validate client proof");
        var M2 = LoginStep3(M1, S);
        return M2;
    }

    public BigInteger LoginStep3(BigInteger M1, BigInteger S)
    {
        return GenerateServerProof(ClientA, M1, S);
    }
    
    private int FindUserIndex(string I)
    {
        for (var i = 0; i < users.Count(); i++)
        {
            if (users[i].login == I)
            {
                return i;
            }
        }

        return -1;
    }
    
    public BigInteger GenerateB(BigInteger verificator)
    {
        b = Helpers.RandomBigIntInString(64).ToSrpBigInt();
        Helpers.Log("b", b.ToString());
        
        var k = Helpers.ComputeK(generator, BigN, Hash);

        var left = (k * verificator) % BigN;
        var right = BigInteger.ModPow(generator, b, BigN);

        B = (left + right) % BigN;
        Helpers.Log("B", B.ToString());
        
        return B;
    }

    public BigInteger ComputeSessionKey(BigInteger verificator, BigInteger A)
    {
        if (A.IsZero) throw new Exception();
        
        var u = Helpers.ComputeU(Hash, A, B);

        var left = A * BigInteger.ModPow(verificator, u, BigN) % BigN;

        return BigInteger.ModPow(left, b, BigN);
    }
    
    public bool ValidateClientProof(BigInteger M1, BigInteger A, BigInteger S)
    {
        return M1 == Helpers.ComputeClientProof(BigN, Hash, A, B, S);
    }

    public BigInteger GenerateServerProof(BigInteger A, BigInteger M1, BigInteger S)
    {
        return Helpers.ComputeServerProof(BigN, Hash, A, M1, S);
    }
}