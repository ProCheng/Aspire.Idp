using System.ComponentModel.DataAnnotations;

namespace IdentityServer4.Quickstart.UI
{
    public class ResetPasswordViewModel
    {
        [Required]
        public string userId { get; set; }


        [Required]
        [StringLength(100, ErrorMessage = "{0}的长度必须至少为{2}个字符，最多为{1}个字符", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "密码和确认密码不匹配")]
        public string ConfirmPassword { get; set; }

        public string Code { get; set; }
        public string AccessCode { get; set; }
    }
}
