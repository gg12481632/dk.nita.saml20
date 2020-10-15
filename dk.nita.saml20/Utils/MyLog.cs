using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace dk.nita.saml20.Utils
{
    static class MyLog
    {
        private static string _path = @"c:\temp\MyLog.txt";
        public static void Write(string text)
        {
            if(File.Exists(_path))
            {
                File.AppendAllLines(_path, new string[] { text } );
            }
            else
            {
                File.WriteAllLines(_path, new string[] { text });
            }
        }
    }
}
