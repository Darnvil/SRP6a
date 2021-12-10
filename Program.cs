// See https://aka.ms/new-console-template for more information

using System.Numerics;
using System.Security.Cryptography;
using SRP;

const int g = 2; // g - generator, modulo N (defined in RFC 5054)
BigInteger N = // N - a large, safe prime (defined in RFC 5054)
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"
        .ToSrpBigInt();


HashAlgorithm hasher = SHA1.Create();
Func<byte[], byte[]> H = i => hasher.ComputeHash(i); // H - hash function

var server = new SrpServer(H, g, N);

bool exit = false;

while (exit != true)
{
    try
    {
        Console.WriteLine("Choose action (Type 'Exit' to exit): \n 1. Register \n 2. Login\n");
        var action = Console.ReadLine();
        switch (action)
        {
            case "1":
                Register();
                break;
            
            case "2":
                Login();
                break;
            
            case "Exit":
                exit = true;
                break;
            
            default:
                continue;
        }
    }
    catch (Exception e)
    {
        Console.WriteLine("Error: " + e);
    }
}


void Register()
{
    var client = new SrpClient(H, g, N);
    
    Console.WriteLine("Your login: ");
    var I = Console.ReadLine();

    Console.WriteLine("Your password: ");
    var P = Console.ReadLine();
    
    client.Register(I, P, server);
}

void Login()
{
    var client = new SrpClient(H, g, N);
    
    Console.WriteLine("Your login: ");
    var I = Console.ReadLine();

    Console.WriteLine("Your password: ");
    var P = Console.ReadLine();
    
    client.Login(I, P, server);
}


