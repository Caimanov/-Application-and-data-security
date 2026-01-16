using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Globalization;

namespace DvoetapnyiZakhystZAnalitykoiu
{
    internal static class Program
    {
        // Сигнатура payload для перевірки, що дані справді належать цій програмі
        static readonly byte[] Magic = Encoding.ASCII.GetBytes("TS2A002\0");

        static int Main()
        {
            Console.OutputEncoding = Encoding.UTF8;

            while (true)
            {
                Console.WriteLine("==============================================");
                Console.WriteLine("Двоетапний захист з аналітикою (AES + LSB BMP)");
                Console.WriteLine("==============================================");
                Console.WriteLine("  1) Захистити файл (AES -> LSB у BMP)");
                Console.WriteLine("  2) Відновити файл (LSB -> AES + перевірка)");
                Console.WriteLine("  3) Показати місткість BMP");
                Console.WriteLine("  0) Вихід");
                Console.Write("Ваш вибір: ");
                var c = (Console.ReadLine() ?? "").Trim();

                try
                {
                    if (c == "0") return 0;

                    if (c == "1")
                    {
                        var inFile = Ask("Вкажіть шлях до вхідного файлу: ", true);
                        var cover = Ask("Вкажіть шлях до покривного BMP (24-bit): ", true);
                        var outBmp = Ask("Вкажіть шлях для stego-BMP: ", false);
                        var pwd = AskPwd("Введіть пароль: ");

                        Protect(inFile, cover, outBmp, pwd);
                        Pause(); Console.Clear();
                        continue;
                    }

                    if (c == "2")
                    {
                        var stego = Ask("Вкажіть шлях до stego-BMP: ", true);
                        var outFile = Ask("Вкажіть шлях для відновленого файлу: ", false);
                        var pwd = AskPwd("Введіть пароль: ");

                        Unprotect(stego, outFile, pwd);
                        Pause(); Console.Clear();
                        continue;
                    }

                    if (c == "3")
                    {
                        var bmp = Ask("Вкажіть шлях до BMP: ", true);
                        ShowCapacity(bmp);
                        Pause(); Console.Clear();
                        continue;
                    }

                    Console.WriteLine("Невірний вибір.");
                    Pause(); Console.Clear();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("ПОМИЛКА: " + ex.Message);
                    Pause(); Console.Clear();
                }
            }
        }

        // Запит та перевірка шляху до файлу
        static string Ask(string prompt, bool exist)
        {
            while (true)
            {
                Console.Write(prompt);
                var p = (Console.ReadLine() ?? "").Trim().Trim('"');
                if (string.IsNullOrWhiteSpace(p)) continue;

                p = Path.GetFullPath(p);

                if (exist && !File.Exists(p))
                {
                    Console.WriteLine("Файл не знайдено.");
                    continue;
                }

                return p;
            }
        }

        // Перевірка мінімальної довжини пароля
        static string AskPwd(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                var s = Console.ReadLine() ?? "";
                if (s.Length < 4)
                {
                    Console.WriteLine("Пароль надто короткий.");
                    continue;
                }
                return s;
            }
        }

        static void Pause()
        {
            Console.Write("\nНатисніть будь-яку клавішу...");
            Console.ReadKey(true);
            Console.WriteLine();
        }

        // ===================== ЕТАП ЗАХИСТУ =====================
        // 1) AES-шифрування → 2) приховування у BMP методом LSB
        static void Protect(string inputFile, string coverBmp, string outStegoBmp, string password)
        {
            var original = File.ReadAllBytes(inputFile);

            // AES-256 з ключем, отриманим з пароля через PBKDF2
            EncryptAes(original, password, out var salt, out var iv, out var cipher);

            // Формування payload (службові дані + шифротекст)
            var payload = BuildPayload(
                salt,
                iv,
                Sha256(original),
                Path.GetFileName(inputFile),
                cipher
            );

            // Вбудовування payload у BMP через LSB
            var bmp = Bmp24.Load(coverBmp);
            bmp.Embed(payload);
            bmp.Save(outStegoBmp);

            Console.WriteLine("\nГАРАЗД: Дані зашифровано та приховано.");
        }

        // ===================== ЕТАП ВІДНОВЛЕННЯ =====================
        // 1) Витяг з LSB → 2) AES-розшифрування → 3) перевірка цілісності
        static void Unprotect(string stegoBmp, string outFile, string password)
        {
            var bmp = Bmp24.Load(stegoBmp);
            var ex = bmp.Extract();

            ParsePayload(ex.Payload, out var salt, out var iv, out var shaOrig, out var name, out var cipher);

            var restored = DecryptAes(cipher, password, salt, iv);

            // Контроль цілісності: SHA-256 має співпадати
            if (!Eq(Sha256(restored), shaOrig))
                throw new CryptographicException("Перевірка цілісності не пройдена.");

            File.WriteAllBytes(outFile, restored);

            Console.WriteLine("\nГАРАЗД: Файл відновлено, цілісність підтверджена.");
        }

        static void ShowCapacity(string bmpPath)
        {
            var bmp = Bmp24.Load(bmpPath);
            Console.WriteLine($"Місткість BMP (LSB): {bmp.CapacityBytes} байт");
        }

        // ===================== КРИПТОГРАФІЯ =====================

        // AES-256-CBC + PBKDF2 (пароль → ключ)
        static void EncryptAes(byte[] plain, string password, out byte[] salt, out byte[] iv, out byte[] cipher)
        {
            salt = RandomNumberGenerator.GetBytes(16);
            iv = RandomNumberGenerator.GetBytes(16);

            using var kdf = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
            using var aes = Aes.Create();

            aes.Key = kdf.GetBytes(32);
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);

            cs.Write(plain, 0, plain.Length);
            cs.FlushFinalBlock();
            cipher = ms.ToArray();
        }

        static byte[] DecryptAes(byte[] cipher, string password, byte[] salt, byte[] iv)
        {
            using var kdf = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
            using var aes = Aes.Create();

            aes.Key = kdf.GetBytes(32);
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);

            cs.Write(cipher, 0, cipher.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }

        static byte[] Sha256(byte[] d)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(d);
        }

        // ===================== PAYLOAD =====================
        // Службова структура, яка зберігається у BMP

        static byte[] BuildPayload(byte[] salt, byte[] iv, byte[] sha, string name, byte[] cipher)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            bw.Write(Magic);
            bw.Write((byte)1);
            bw.Write(salt);
            bw.Write(iv);
            bw.Write(sha);

            var nameBytes = Encoding.UTF8.GetBytes(name);
            bw.Write((ushort)nameBytes.Length);
            bw.Write(nameBytes);

            bw.Write(cipher.Length);
            bw.Write(cipher);

            return ms.ToArray();
        }

        static void ParsePayload(byte[] payload, out byte[] salt, out byte[] iv, out byte[] sha, out string name, out byte[] cipher)
        {
            using var ms = new MemoryStream(payload);
            using var br = new BinaryReader(ms);

            if (!Eq(br.ReadBytes(Magic.Length), Magic))
                throw new InvalidDataException("Невірний payload.");

            br.ReadByte(); // version
            salt = br.ReadBytes(16);
            iv = br.ReadBytes(16);
            sha = br.ReadBytes(32);

            var nLen = br.ReadUInt16();
            name = Encoding.UTF8.GetString(br.ReadBytes(nLen));

            var clen = br.ReadInt32();
            cipher = br.ReadBytes(clen);
        }

        // ===================== BMP + LSB =====================
        // Реалізація роботи з BMP без System.Drawing

        sealed class Bmp24
        {
            public int Width { get; private set; }
            public int Height { get; private set; }
            public long CapacityBytes => PixelSize / 8;

            byte[] Bytes;
            int PixelOffset, PixelSize;

            public static Bmp24 Load(string path)
            {
                var b = File.ReadAllBytes(path);

                int off = BitConverter.ToInt32(b, 10);
                int w = BitConverter.ToInt32(b, 18);
                int h = Math.Abs(BitConverter.ToInt32(b, 22));
                int stride = ((w * 3 + 3) / 4) * 4;

                return new Bmp24
                {
                    Bytes = b,
                    PixelOffset = off,
                    PixelSize = stride * h,
                    Width = w,
                    Height = h
                };
            }

            public void Save(string path) => File.WriteAllBytes(path, Bytes);

            // Вбудовування даних у найменш значущий біт
            public void Embed(byte[] payload)
            {
                var len = BitConverter.GetBytes(payload.Length);
                var data = new byte[4 + payload.Length];

                Buffer.BlockCopy(len, 0, data, 0, 4);
                Buffer.BlockCopy(payload, 0, data, 4, payload.Length);

                int bit = 0;
                for (int i = PixelOffset; bit < data.Length * 8; i++)
                    Bytes[i] = (byte)((Bytes[i] & 0xFE) | ((data[bit / 8] >> (bit++ % 8)) & 1));
            }

            public (byte[] Payload, int PayloadLen, long Bits, int Bytes) Extract()
            {
                var lenBytes = new byte[4];
                ExtractInto(lenBytes, 0, 4);

                int plen = BitConverter.ToInt32(lenBytes, 0);
                var payload = new byte[plen];
                ExtractInto(payload, 4, plen);

                return (payload, plen, (plen + 4) * 8, plen + 4);
            }

            void ExtractInto(byte[] target, int skipBytes, int readBytes)
            {
                int bit = 0, skipBits = skipBytes * 8;

                for (int i = PixelOffset; bit < readBytes * 8 + skipBits; i++)
                {
                    if (bit >= skipBits)
                        target[(bit - skipBits) / 8] |= (byte)((Bytes[i] & 1) << ((bit - skipBits) % 8));
                    bit++;
                }
            }
        }

        static bool Eq(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }
}
