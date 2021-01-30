using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace ByteBank.Forum.App_Start.Identity
{
    public class SenhaValidador : IIdentityValidator<string>
    {
        public int TamanhoRequerido { get; set; }
        public bool ObrigatorioCaracteresEspeciais { get; set; }
        public bool ObrigatorioLowerCase { get; set; }
        public bool ObrigatorioUpperCase { get; set; }
        public bool ObrigatorioDigitos { get; set; }
        public async Task<IdentityResult> ValidateAsync(string item)
        {
            var erros = new List<string>();

            if(!VerificaTamanhoRequerido(item))
                erros.Add($"A senha deve conter no mínimo {TamanhoRequerido} caracteres.");

            if (ObrigatorioLowerCase && !VerificaLowerCase(item))
                erros.Add("A senha deve conter letras minúsculas.");

            if (ObrigatorioUpperCase && !VerificaUpperCase(item))
                erros.Add("A senha deve conter letras maiúsculas.");

            if (ObrigatorioCaracteresEspeciais && !VerificaCaracteresEspeciais(item))
                erros.Add("A senha deve conter caracteres especiais.");

            if (ObrigatorioDigitos && !VerificaDigitos(item))
                erros.Add("A senha deve conter no mínimo 1 dígito.");

            if (erros.Any())
                return IdentityResult.Failed(erros.ToArray());
            else
                return IdentityResult.Success;
        }

        private bool VerificaTamanhoRequerido(string senha) =>  senha?.Length >= TamanhoRequerido;

        private bool VerificaCaracteresEspeciais(string senha) => 
            Regex.IsMatch(senha, @"[~`!@#$%^&*()+=|\\{}':;.,<>/?[\]""_-]");

        private bool VerificaLowerCase(string senha) => senha.Any(char.IsLower);

        private bool VerificaUpperCase(string senha) => senha.Any(char.IsUpper);

        private bool VerificaDigitos(string senha) => senha.Any(char.IsDigit);
    }
}