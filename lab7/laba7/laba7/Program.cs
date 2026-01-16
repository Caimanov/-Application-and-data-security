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
                        var inFile = Ask("Вкажіть шлях до вхідного файлу: ", exist: true);
                        var cover = Ask("Вкажіть шлях до покривного BMP (24-bit, без стиснення): ", exist: true);
                        var outBmp = Ask("Вкажіть шлях для stego-BMP: ", exist: false);
                        var pwd = AskPwd("Введіть пароль: ");
                        Protect(inFile, cover, outBmp, pwd);
                        Pause(); Console.Clear(); continue;
                    }
                    if (c == "2")
                    {
                        var stego = Ask("Вкажіть шлях до stego-BMP: ", exist: true);
                        var outFile = Ask("Вкажіть шлях для відновленого файлу: ", exist: false);
                        var pwd = AskPwd("Введіть пароль: ");
                        Unprotect(stego, outFile, pwd);
                        Pause(); Console.Clear(); continue;
                    }
                    if (c == "3")
                    {
                        var bmp = Ask("Вкажіть шлях до BMP: ", exist: true);
                        ShowCapacity(bmp);
                        Pause(); Console.Clear(); continue;
                    }

                    Console.WriteLine("Невірний вибір."); Pause(); Console.Clear();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("ПОМИЛКА: " + ex.Message);
                    Pause(); Console.Clear();
                }
            }
        }

        static string Ask(string prompt, bool exist)
        {
            while (true)
            {
                Console.Write(prompt);
                var p = (Console.ReadLine() ?? "").Trim().Trim('"');
                if (string.IsNullOrWhiteSpace(p)) { Console.WriteLine("Порожній шлях."); continue; }
                p = Path.GetFullPath(p);

                if (exist)
                {
                    if (!File.Exists(p)) { Console.WriteLine("Файл не знайдено: " + p); continue; }
                }
                else
                {
                    var dir = Path.GetDirectoryName(p);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    { Console.WriteLine("Папка не існує: " + dir); continue; }
                }
                return p;
            }
        }

        static string AskPwd(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                var s = Console.ReadLine() ?? "";
                if (s.Length < 4) { Console.WriteLine("Мінімум 4 символи."); continue; }
                return s;
            }
        }

        static void Pause()
        {
            Console.Write("\nНатисніть будь-яку клавішу, щоб продовжити...");
            Console.ReadKey(true);
            Console.WriteLine();
        }

        // ===================== PROTECT / UNPROTECT =====================

        static void Protect(string inputFile, string coverBmp, string outStegoBmp, string password)
        {
            var r = new Report
            {
                Rezhym = "захист",
                ChasUTC = DateTime.UtcNow.ToString("o"),
                VkhidnyiFayl = inputFile,
                PokryvneZobrazhennia = coverBmp,
                VykhidneStegoZobrazhennia = outStegoBmp
            };

            var original = File.ReadAllBytes(inputFile);
            r.RozmirOriginaluB = original.Length;
            r.Sha256Originalu = Hex(Sha256(original));

            var swAes = Stopwatch.StartNew();
            EncryptAes(original, password, out var salt, out var iv, out var cipher);
            swAes.Stop();
            r.ChasEtap1Ms = swAes.ElapsedMilliseconds;
            r.RozmirShyfroTekstuB = cipher.Length;

            var payload = BuildPayload(salt, iv, HexToBytes(r.Sha256Originalu), Path.GetFileName(inputFile), cipher);
            r.RozmirPayloadB = payload.Length;

            var bmp = Bmp24.Load(coverBmp);
            r.BmpWidth = bmp.Width; r.BmpHeight = bmp.Height;
            r.MistkistPokryvnohoB = bmp.CapacityBytes;
            r.PotribnoVbuduvatyB = 4L + payload.Length;
            if (r.PotribnoVbuduvatyB > r.MistkistPokryvnohoB)
                throw new InvalidOperationException($"Недостатня місткість BMP. Потрібно {r.PotribnoVbuduvatyB} байт, є {r.MistkistPokryvnohoB} байт.");

            var swLsb = Stopwatch.StartNew();
            var st = bmp.Embed(payload);
            bmp.Save(outStegoBmp);
            swLsb.Stop();

            r.ChasEtap2Ms = swLsb.ElapsedMilliseconds;
            r.RozmirStegoZobrazhenniaB = new FileInfo(outStegoBmp).Length;
            r.LsbBityZapysano = st.Bits; r.LsbBaitiZapysano = st.Bytes;

            r.ZahalnyiChasMs = r.ChasEtap1Ms + r.ChasEtap2Ms;
            r.VidstotokVykorystanniaMistkosti = r.MistkistPokryvnohoB > 0
                ? (double)r.PotribnoVbuduvatyB / r.MistkistPokryvnohoB * 100.0 : 0.0;

            var reportPath = Path.Combine(Path.GetDirectoryName(outStegoBmp) ?? ".", "zvit_zakhyst.json");
            File.WriteAllText(reportPath, r.ToJson(), Encoding.UTF8);

            Console.WriteLine("\nГАРАЗД: Зашифровано та приховано у BMP.");
            Console.WriteLine("Stego-BMP: " + outStegoBmp);
            Console.WriteLine("Звіт: " + reportPath);
            Console.WriteLine($"Час: AES {r.ChasEtap1Ms} мс, LSB {r.ChasEtap2Ms} мс (разом {r.ZahalnyiChasMs} мс)");
            Console.WriteLine($"Використано місткості: {r.VidstotokVykorystanniaMistkosti:F2}%");
        }

        static void Unprotect(string stegoBmp, string outFile, string password)
        {
            var r = new Report
            {
                Rezhym = "відновлення",
                ChasUTC = DateTime.UtcNow.ToString("o"),
                StegoZobrazhennia = stegoBmp,
                VykhidnyiFayl = outFile
            };

            var bmp = Bmp24.Load(stegoBmp);
            r.BmpWidth = bmp.Width; r.BmpHeight = bmp.Height;
            r.MistkistPokryvnohoB = bmp.CapacityBytes;

            var swLsb = Stopwatch.StartNew();
            var ex = bmp.Extract();
            swLsb.Stop();

            r.ChasEtap2Ms = swLsb.ElapsedMilliseconds;
            r.RozmirPayloadB = ex.PayloadLen;
            r.LsbBityProchytano = ex.Bits; r.LsbBaitiProchytano = ex.Bytes;

            ParsePayload(ex.Payload, out var salt, out var iv, out var shaOrig, out var name, out var cipher);
            r.OriginalnaNazvaZPayload = name;
            r.RozmirShyfroTekStuB = cipher.Length; // (залишено для сумісності з ТЗ через JSON ключі)
            r.RozmirShyfroTekStuB = 0; // заглушка, не використовується
            r.RozmirShyfroTekStuB = 0;

            r.RozmirShyfroTekstuB = cipher.Length;
            r.OchikuvanyiSha256Originalu = Hex(shaOrig);

            var swAes = Stopwatch.StartNew();
            var restored = DecryptAes(cipher, password, salt, iv);
            swAes.Stop();

            r.ChasEtap1Ms = swAes.ElapsedMilliseconds;
            r.RozmirVidnovlenohoB = restored.Length;
            r.Sha256Vidnovlenoho = Hex(Sha256(restored));

            r.TsilisnistOk = string.Equals(r.Sha256Vidnovlenoho, r.OchikuvanyiSha256Originalu, StringComparison.OrdinalIgnoreCase);
            if (!r.TsilisnistOk)
                throw new CryptographicException("Перевірка цілісності не пройдена (SHA-256 не збігається). Невірний пароль або дані пошкоджені.");

            File.WriteAllBytes(outFile, restored);
            r.ZahalnyiChasMs = r.ChasEtap1Ms + r.ChasEtap2Ms;

            var reportPath = Path.Combine(Path.GetDirectoryName(outFile) ?? ".", "zvit_vidnovlennia.json");
            File.WriteAllText(reportPath, r.ToJson(), Encoding.UTF8);

            Console.WriteLine("\nГАРАЗД: Витягнуто, розшифровано, цілісність OK.");
            Console.WriteLine("Вихідний файл: " + outFile);
            Console.WriteLine("Оригінальна назва з payload: " + r.OriginalnaNazvaZPayload);
            Console.WriteLine("Звіт: " + reportPath);
            Console.WriteLine($"Час: LSB {r.ChasEtap2Ms} мс, AES {r.ChasEtap1Ms} мс (разом {r.ZahalnyiChasMs} мс)");
        }

        static void ShowCapacity(string bmpPath)
        {
            var bmp = Bmp24.Load(bmpPath);
            Console.WriteLine($"\nBMP: {bmp.Width}x{bmp.Height} (24-bit)");
            Console.WriteLine($"Місткість LSB (1 біт на байт пікселів): {bmp.CapacityBytes} байт");
        }

        // ===================== CRYPTO =====================

        static void EncryptAes(byte[] plain, string password, out byte[] salt, out byte[] iv, out byte[] cipher)
        {
            salt = Rnd(16); iv = Rnd(16);
            using var kdf = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
            using var aes = Aes.Create();
            aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
            aes.Key = kdf.GetBytes(32); aes.IV = iv;

            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            { cs.Write(plain, 0, plain.Length); cs.FlushFinalBlock(); }
            cipher = ms.ToArray();
        }

        static byte[] DecryptAes(byte[] cipher, string password, byte[] salt, byte[] iv)
        {
            using var kdf = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
            using var aes = Aes.Create();
            aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
            aes.Key = kdf.GetBytes(32); aes.IV = iv;

            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
            { cs.Write(cipher, 0, cipher.Length); cs.FlushFinalBlock(); }
            return ms.ToArray();
        }

        static byte[] Sha256(byte[] d) { using var sha = SHA256.Create(); return sha.ComputeHash(d); }
        static byte[] Rnd(int n) { var b = new byte[n]; using var rng = RandomNumberGenerator.Create(); rng.GetBytes(b); return b; }

        // ===================== PAYLOAD =====================

        static byte[] BuildPayload(byte[] salt, byte[] iv, byte[] sha, string name, byte[] cipher)
        {
            var nameBytes = Encoding.UTF8.GetBytes(name ?? "vidnovleno.bin");
            if (nameBytes.Length > ushort.MaxValue) throw new InvalidOperationException("Назва файлу занадто довга.");

            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);
            bw.Write(Magic); bw.Write((byte)1);
            bw.Write(salt); bw.Write(iv); bw.Write(sha);
            bw.Write((ushort)nameBytes.Length); bw.Write(nameBytes);
            bw.Write(cipher.Length); bw.Write(cipher);
            bw.Flush();
            return ms.ToArray();
        }

        static void ParsePayload(byte[] payload, out byte[] salt, out byte[] iv, out byte[] sha, out string name, out byte[] cipher)
        {
            using var ms = new MemoryStream(payload);
            using var br = new BinaryReader(ms);

            var m = br.ReadBytes(Magic.Length);
            if (m.Length != Magic.Length || !Eq(m, Magic)) throw new InvalidDataException("Невірний MAGIC payload.");
            var ver = br.ReadByte();
            if (ver != 1) throw new InvalidDataException("Непідтримувана версія payload: " + ver);

            salt = br.ReadBytes(16);
            iv = br.ReadBytes(16);
            sha = br.ReadBytes(32);

            var nLen = br.ReadUInt16();
            name = Encoding.UTF8.GetString(br.ReadBytes(nLen));

            var clen = br.ReadInt32();
            if (clen < 0 || clen > payload.Length - ms.Position) throw new InvalidDataException("Пошкоджена довжина шифротексту.");
            cipher = br.ReadBytes(clen);
        }

        // ===================== BMP 24 + LSB (NO System.Drawing) =====================

        sealed class Bmp24
        {
            public int Width { get; private set; }
            public int Height { get; private set; }
            public long CapacityBytes => PixelSize / 8L;

            byte[] Bytes;
            int PixelOffset, PixelSize;

            Bmp24() { }

            public static Bmp24 Load(string path)
            {
                var b = File.ReadAllBytes(path);
                if (b.Length < 54 || b[0] != (byte)'B' || b[1] != (byte)'M')
                    throw new InvalidDataException("Це не BMP.");

                int off = BitConverter.ToInt32(b, 10);
                int dib = BitConverter.ToInt32(b, 14);
                if (dib < 40) throw new InvalidDataException("Потрібен BITMAPINFOHEADER.");

                int w = BitConverter.ToInt32(b, 18);
                int hRaw = BitConverter.ToInt32(b, 22);
                int h = Math.Abs(hRaw);
                short bpp = BitConverter.ToInt16(b, 28);
                int comp = BitConverter.ToInt32(b, 30);

                if (bpp != 24) throw new InvalidDataException("Потрібен BMP 24-bit.");
                if (comp != 0) throw new InvalidDataException("Потрібен BMP без стиснення.");

                int stride = ((w * 3 + 3) / 4) * 4;
                int pixSize = stride * h;
                if (off < 54 || off + pixSize > b.Length) throw new InvalidDataException("BMP пошкоджений.");

                return new Bmp24 { Bytes = b, PixelOffset = off, PixelSize = pixSize, Width = w, Height = h };
            }

            public void Save(string path) => File.WriteAllBytes(path, Bytes);

            public (long Bits, int Bytes) Embed(byte[] payload)
            {
                var len = BitConverter.GetBytes(payload.Length);
                var data = new byte[4 + payload.Length];
                Buffer.BlockCopy(len, 0, data, 0, 4);
                Buffer.BlockCopy(payload, 0, data, 4, payload.Length);

                long needBits = (long)data.Length * 8L;
                if (needBits > PixelSize) throw new InvalidOperationException("Не вистачає місткості BMP.");

                int bit = 0, start = PixelOffset, end = PixelOffset + PixelSize;
                for (int i = start; i < end && bit < needBits; i++)
                    Bytes[i] = (byte)((Bytes[i] & 0xFE) | GetBit(data, bit++));
                return (needBits, data.Length);
            }

            public (byte[] Payload, int PayloadLen, long Bits, int Bytes) Extract()
            {
                var lenBytes = new byte[4];
                ExtractInto(lenBytes, 0, 4);

                int plen = BitConverter.ToInt32(lenBytes, 0);
                if (plen <= 0 || plen > 200_000_000) throw new InvalidDataException("Невірна довжина payload: " + plen);

                var payload = new byte[plen];
                ExtractInto(payload, 4, plen);

                long bits = (long)(4 + plen) * 8L;
                return (payload, plen, bits, 4 + plen);
            }

            void ExtractInto(byte[] target, int skipBytes, int readBytes)
            {
                long skipBits = (long)skipBytes * 8L, needBits = (long)readBytes * 8L;
                long g = 0, t = 0;
                int start = PixelOffset, end = PixelOffset + PixelSize;

                for (int i = start; i < end; i++)
                {
                    if (g >= skipBits && t < needBits) SetBit(target, (int)t++, (byte)(Bytes[i] & 1));
                    g++;
                    if (t >= needBits) return;
                }
                throw new InvalidOperationException("Недостатньо бітів у BMP.");
            }

            static byte GetBit(byte[] data, int bitIndex)
            {
                int bi = bitIndex / 8, bo = bitIndex % 8;
                return (byte)((data[bi] >> bo) & 1);
            }

            static void SetBit(byte[] data, int bitIndex, byte bit)
            {
                int bi = bitIndex / 8, bo = bitIndex % 8;
                data[bi] = bit == 1 ? (byte)(data[bi] | (1 << bo)) : (byte)(data[bi] & ~(1 << bo));
            }
        }

        // ===================== UTIL JSON/HEX =====================

        static bool Eq(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        static string Hex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++) sb.Append(bytes[i].ToString("x2"));
            return sb.ToString();
        }

        static byte[] HexToBytes(string hex)
        {
            if (hex == null) throw new ArgumentNullException(nameof(hex));
            if (hex.Length % 2 != 0) throw new ArgumentException("Hex має парну довжину.");
            var b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        // ===================== REPORT (MIN JSON) =====================

        sealed class Report
        {
            public string Rezhym, ChasUTC;
            public string VkhidnyiFayl, PokryvneZobrazhennia, VykhidneStegoZobrazhennia;
            public string StegoZobrazhennia, VykhidnyiFayl;

            public long ChasEtap1Ms, ChasEtap2Ms, ZahalnyiChasMs;
            public long RozmirOriginaluB, RozmirVidnovlenohoB, RozmirShyfroTekstuB, RozmirPayloadB, RozmirStegoZobrazhenniaB;

            public int BmpWidth, BmpHeight;
            public long MistkistPokryvnohoB, PotribnoVbuduvatyB;
            public double VidstotokVykorystanniaMistkosti;

            public long LsbBityZapysano, LsbBityProchytano;
            public int LsbBaitiZapysano, LsbBaitiProchytano;

            public string Sha256Originalu, OchikuvanyiSha256Originalu, Sha256Vidnovlenoho;
            public bool TsilisnistOk;
            public string OriginalnaNazvaZPayload;

            // добавлены поля-заглушки, чтобы не ломать компиляцию из-за сокращений выше (не используются)
            public long RozmirShyfroTekStuB;

            public string ToJson()
            {
                var sb = new StringBuilder();
                sb.Append("{\n");
                A(sb, "режим", Rezhym);
                A(sb, "часUTC", ChasUTC);

                A(sb, "вхіднийФайл", VkhidnyiFayl);
                A(sb, "покривнеЗображення", PokryvneZobrazhennia);
                A(sb, "вихіднеStegoЗображення", VykhidneStegoZobrazhennia);

                A(sb, "stegoЗображення", StegoZobrazhennia);
                A(sb, "вихіднийФайл", VykhidnyiFayl);

                A(sb, "часЕтап1Мс", ChasEtap1Ms);
                A(sb, "часЕтап2Мс", ChasEtap2Ms);
                A(sb, "загальнийЧасМс", ZahalnyiChasMs);

                A(sb, "розмірОригіналуБ", RozmirOriginaluB);
                A(sb, "розмірВідновленогоБ", RozmirVidnovlenohoB);
                A(sb, "розмірШифротекстуБ", RozmirShyfroTekstuB);
                A(sb, "розмірPayloadБ", RozmirPayloadB);
                A(sb, "розмірStegoЗображенняБ", RozmirStegoZobrazhenniaB);

                A(sb, "bmpШирина", BmpWidth);
                A(sb, "bmpВисота", BmpHeight);
                A(sb, "місткістьПокривногоБ", MistkistPokryvnohoB);
                A(sb, "потрібноВбудуватиБ", PotribnoVbuduvatyB);
                A(sb, "відсотокВикористанняМісткості", VidstotokVykorystanniaMistkosti);

                A(sb, "lsbБітиЗаписано", LsbBityZapysano);
                A(sb, "lsbБітиПрочитано", LsbBityProchytano);
                A(sb, "lsbБайтиЗаписано", LsbBaitiZapysano);
                A(sb, "lsbБайтиПрочитано", LsbBaitiProchytano);

                A(sb, "sha256Оригіналу", Sha256Originalu);
                A(sb, "очікуванийSha256Оригіналу", OchikuvanyiSha256Originalu);
                A(sb, "sha256Відновленого", Sha256Vidnovlenoho);
                A(sb, "цілісністьOK", TsilisnistOk);
                A(sb, "оригінальнаНазваЗPayload", OriginalnaNazvaZPayload, last: true);
                sb.Append("\n}\n");
                return sb.ToString();
            }

            static void A(StringBuilder sb, string k, string v, bool last = false)
            { if (v != null) sb.Append($"  \"{E(k)}\": \"{E(v)}\"{(last ? "" : ",")}\n"); }

            static void A(StringBuilder sb, string k, long v, bool last = false)
            { sb.Append($"  \"{E(k)}\": {v}{(last ? "" : ",")}\n"); }

            static void A(StringBuilder sb, string k, int v, bool last = false)
            { sb.Append($"  \"{E(k)}\": {v}{(last ? "" : ",")}\n"); }

            static void A(StringBuilder sb, string k, double v, bool last = false)
            { sb.Append($"  \"{E(k)}\": {v.ToString(CultureInfo.InvariantCulture)}{(last ? "" : ",")}\n"); }

            static void A(StringBuilder sb, string k, bool v, bool last = false)
            { sb.Append($"  \"{E(k)}\": {(v ? "true" : "false")}{(last ? "" : ",")}\n"); }

            static string E(string s) => (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}
