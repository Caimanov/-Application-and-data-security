using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Text;

namespace StegoLSB
{
    internal class Program
    {
        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("=== Стеганографія LSB ===\n");
            Console.WriteLine("1) Приховати повідомлення");
            Console.WriteLine("2) Витягнути повідомлення");
            Console.Write("Вибір: ");
            string option = Console.ReadLine();

            switch (option)
            {
                case "1":
                    RunHide();
                    break;
                case "2":
                    RunExtract();
                    break;
                default:
                    Console.WriteLine("Невірний вибір");
                    break;
            }

            Console.WriteLine("Натисніть Enter для виходу...");
            Console.ReadLine();
        }

        static void RunHide()
        {
            Console.Write("Вхідне зображення (PNG/BMP): ");
            string input = Console.ReadLine();
            Console.Write("Вихідне зображення (PNG): ");
            string output = Console.ReadLine();
            Console.Write("Повідомлення для приховування: ");
            string message = Console.ReadLine() ?? "";

            try
            {
                HideMessage(input, output, message);
                Console.WriteLine("Повідомлення приховано!");
                AnalyzeImage(input, output);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Помилка: " + ex.Message);
            }
        }

        static void RunExtract()
        {
            Console.Write("Зображення зі схованим текстом: ");
            string input = Console.ReadLine();

            try
            {
                string msg = ExtractMessage(input);
                Console.WriteLine(" Витягнуте повідомлення:\n" + msg);
            }
            catch (Exception ex)
            {
                Console.WriteLine(" Помилка: " + ex.Message);
            }
        }

        // ------------------ Стеганографія ------------------
        public static void HideMessage(string sourcePath, string destPath, string message)
        {
            if (!File.Exists(sourcePath)) throw new FileNotFoundException("Файл не знайдено");

            Bitmap bmp = new Bitmap(sourcePath);

            byte[] msgBytes = Encoding.UTF8.GetBytes(message);
            byte[] header = BitConverter.GetBytes(msgBytes.Length);
            byte[] data = header.Concat(msgBytes).ToArray();

            bool[] bits = BytesToBits(data);

            int totalBits = bits.Length;
            int capacity = bmp.Width * bmp.Height * 3;

            if (totalBits > capacity) throw new Exception($"Повідомлення занадто велике ({totalBits} біт, доступно {capacity})");

            int bitIndex = 0;
            for (int y = 0; y < bmp.Height; y++)
            {
                for (int x = 0; x < bmp.Width; x++)
                {
                    if (bitIndex >= totalBits) break;

                    Color pixel = bmp.GetPixel(x, y);
                    byte r = pixel.R, g = pixel.G, b = pixel.B;

                    r = bitIndex < totalBits ? SetLSB(r, bits[bitIndex++]) : r;
                    g = bitIndex < totalBits ? SetLSB(g, bits[bitIndex++]) : g;
                    b = bitIndex < totalBits ? SetLSB(b, bits[bitIndex++]) : b;

                    bmp.SetPixel(x, y, Color.FromArgb(pixel.A, r, g, b));
                }
            }

            bmp.Save(destPath, ImageFormat.Png);
            Console.WriteLine("Бінарне повідомлення (перші 64 біти):");
            Console.WriteLine(string.Join("", bits.Take(64).Select(b => b ? "1" : "0")));
        }

        public static string ExtractMessage(string path)
        {
            if (!File.Exists(path)) throw new FileNotFoundException("Файл не знайдено");

            Bitmap bmp = new Bitmap(path);

            bool[] lengthBits = new bool[32];
            int index = 0;

            foreach (var px in bmp.GetPixels())
            {
                if (index >= 32) break;
                lengthBits[index++] = (px.R & 1) == 1;
                if (index < 32) lengthBits[index++] = (px.G & 1) == 1;
                if (index < 32) lengthBits[index++] = (px.B & 1) == 1;
            }

            int msgLen = BitConverter.ToInt32(BitsToBytes(lengthBits), 0);
            if (msgLen <= 0) return "";

            int totalBits = msgLen * 8;
            bool[] msgBits = new bool[totalBits];
            int bitIndex = 0, start = 32;

            foreach (var px in bmp.GetPixels())
            {
                if (bitIndex >= start + totalBits) break;

                if (bitIndex >= start && bitIndex < start + totalBits) msgBits[bitIndex - start] = (px.R & 1) == 1;
                bitIndex++;
                if (bitIndex >= start + totalBits) break;

                if (bitIndex >= start && bitIndex < start + totalBits) msgBits[bitIndex - start] = (px.G & 1) == 1;
                bitIndex++;
                if (bitIndex >= start + totalBits) break;

                if (bitIndex >= start && bitIndex < start + totalBits) msgBits[bitIndex - start] = (px.B & 1) == 1;
                bitIndex++;
            }

            return Encoding.UTF8.GetString(BitsToBytes(msgBits));
        }

        // ------------------ Допоміжні ------------------
        public static byte SetLSB(byte value, bool bit) => (byte)((value & 0xFE) | (bit ? 1 : 0));

        public static bool[] BytesToBits(byte[] data)
        {
            bool[] bits = new bool[data.Length * 8];
            for (int i = 0; i < data.Length; i++)
                for (int j = 0; j < 8; j++)
                    bits[i * 8 + j] = ((data[i] >> (7 - j)) & 1) == 1;
            return bits;
        }

        public static byte[] BitsToBytes(bool[] bits)
        {
            int byteCount = (bits.Length + 7) / 8;
            byte[] bytes = new byte[byteCount];
            for (int i = 0; i < bits.Length; i++)
            {
                if (bits[i])
                    bytes[i / 8] |= (byte)(1 << (7 - (i % 8)));
            }
            return bytes;
        }

        // ------------------ Аналіз ------------------
        public static void AnalyzeImage(string originalPath, string modifiedPath)
        {
            Bitmap a = new Bitmap(originalPath);
            Bitmap b = new Bitmap(modifiedPath);

            if (a.Width != b.Width || a.Height != b.Height)
            {
                Console.WriteLine("Різні розміри зображень.");
                return;
            }

            int changedPixels = 0;
            int changedChannels = 0;
            int maxDiff = 0;
            long totalChannels = a.Width * a.Height * 3;
            long sumDiff = 0;

            for (int y = 0; y < a.Height; y++)
            {
                for (int x = 0; x < a.Width; x++)
                {
                    Color p1 = a.GetPixel(x, y);
                    Color p2 = b.GetPixel(x, y);

                    int dr = Math.Abs(p1.R - p2.R);
                    int dg = Math.Abs(p1.G - p2.G);
                    int db = Math.Abs(p1.B - p2.B);

                    sumDiff += dr + dg + db;
                    maxDiff = Math.Max(maxDiff, Math.Max(dr, Math.Max(dg, db)));

                    if (dr != 0) changedChannels++;
                    if (dg != 0) changedChannels++;
                    if (db != 0) changedChannels++;
                    if (dr + dg + db != 0) changedPixels++;
                }
            }

            Console.WriteLine($"Змінено пікселів: {changedPixels} ({100.0 * changedPixels / (a.Width * a.Height):F2}%)");
            Console.WriteLine($"Змінено каналів: {changedChannels} ({100.0 * changedChannels / totalChannels:F2}%)");
            Console.WriteLine($"Максимальна різниця каналу: {maxDiff}");
            Console.WriteLine($"Середня різниця каналу: {(double)sumDiff / totalChannels:F4}");
        }
    }

    // ------------------ Розширення для перебору пікселів ------------------
    static class BitmapExtensions
    {
        public static System.Collections.Generic.IEnumerable<Color> GetPixels(this Bitmap bmp)
        {
            for (int y = 0; y < bmp.Height; y++)
                for (int x = 0; x < bmp.Width; x++)
                    yield return bmp.GetPixel(x, y);
        }
    }
}
