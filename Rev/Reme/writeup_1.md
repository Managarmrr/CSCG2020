# reme Part 1

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Mitigations](#3-mitigations)

## 1. Challenge

**Category**: `Reverse Engineering`  
**Difficulty**: `Easy`  
**Author**: `0x4d5a`  
**Attachments**: [ReMe.dll](https://static.allesctf.net/challenges/e5971550aac869a054b67c9823148cf90470f7463de6a6cbb45f184d50845519/ReMe.dll)
[ReMe.deps.json](https://static.allesctf.net/challenges/9be7b4ca4a698158d6fbc53cd88a5d83d65cd3ccbd1a83728aca2418263dfd8d/ReMe.deps.json)
[ReMe..runtimeconfig.json](https://static.allesctf.net/challenges/9ada7e7cabd6ad48ea6781e31fd6b30eab772558744fc996d9523c7b0e04e9e9/ReMe.runtimeconfig.json)  
**Description**:

.NET Reversing can't be that hard, right? But I've got some twists waiting for you 😈

Execute with .NET Core Runtime 2.2 with windows, e.g. dotnet ReMe.dll

## 2. Having a look

In this challenge we are provided with a `DLL`. Looking at it in `dnSpy` we
can see that if tries to verify the flag against a hardcoded string which is
decrypted on-the-fly. We can just use an online tool such as
https://dotnetfiddle.net/ and paste the code in there.

```csharp
// Token: 0x06000013 RID: 19 RVA: 0x00002E80 File Offset: 0x00001080
public static string Decrypt(string cipherText)
{
	string text = "A_Wise_Man_Once_Told_Me_Obfuscation_Is_Useless_Anyway";
	cipherText = cipherText.Replace(" ", "+");
	byte[] array = Convert.FromBase64String(cipherText);
	using (Aes aes = Aes.Create()) {
		Rfc2898DeriveBytes rfc2898DeriveBytes =
			new Rfc2898DeriveBytes(text, new byte[] {
				73, 118, 97, 110, 32, 77, 101,
				100, 118, 101, 100, 101, 118
				});
		aes.Key = rfc2898DeriveBytes.GetBytes(32);
		aes.IV = rfc2898DeriveBytes.GetBytes(16);
		using (MemoryStream memoryStream = new MemoryStream()) {
			using (CryptoStream cryptoStream =
				new CryptoStream(memoryStream, aes.CreateDecryptor(), 1)) {
				cryptoStream.Write(array, 0, array.Length);
				cryptoStream.Close();
			}
			cipherText = Encoding.Unicode.GetString(memoryStream.ToArray());
		}
	}
	return cipherText;
}

// Console.WriteLine(Program.Decrypt("D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I="));
```

Doing so will get us the flag: `CSCG{CanIHazFlag?}`

## 3. Mitigations

There is no point in talking about mitigation in reversing challenges.
Although you could hash the whole flag.
