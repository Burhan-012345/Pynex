document.addEventListener("DOMContentLoaded", function () {
  // Toggle password visibility
  const toggleButtons = document.querySelectorAll(".toggle-password");

  toggleButtons.forEach((button) => {
    button.addEventListener("click", function () {
      const passwordInput = this.previousElementSibling;
      const type =
        passwordInput.getAttribute("type") === "password" ? "text" : "password";
      passwordInput.setAttribute("type", type);

      // Toggle eye icon
      const icon = this.querySelector("i");
      if (type === "password") {
        icon.className = "fas fa-eye";
      } else {
        icon.className = "fas fa-eye-slash";
      }
    });
  });

  // OTP input auto-focus and navigation
  const otpInputs = document.querySelectorAll(".otp-digit");
  if (otpInputs.length > 0) {
    otpInputs[0].focus();

    otpInputs.forEach((input, index) => {
      input.addEventListener("input", function () {
        if (this.value.length === 1 && index < otpInputs.length - 1) {
          otpInputs[index + 1].focus();
        }

        // Auto-submit when all digits are filled
        if (index === otpInputs.length - 1 && this.value.length === 1) {
          const allFilled = Array.from(otpInputs).every(
            (input) => input.value.length === 1
          );
          if (allFilled) {
            document
              .getElementById("verifyOtpForm")
              .dispatchEvent(new Event("submit"));
          }
        }
      });

      input.addEventListener("keydown", function (e) {
        if (e.key === "Backspace" && this.value === "" && index > 0) {
          otpInputs[index - 1].focus();
        }
      });

      input.addEventListener("paste", function (e) {
        e.preventDefault();
        const pasteData = e.clipboardData
          .getData("text")
          .slice(0, otpInputs.length);
        pasteData.split("").forEach((char, idx) => {
          if (otpInputs[idx]) {
            otpInputs[idx].value = char;
          }
        });

        // Focus last input
        if (otpInputs[pasteData.length - 1]) {
          otpInputs[pasteData.length - 1].focus();
        }
      });
    });
  }

  // Password strength indicator
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  passwordInputs.forEach((input) => {
    input.addEventListener("input", function () {
      const strengthIndicator =
        this.parentNode.querySelector(".password-strength");
      if (strengthIndicator) {
        const strength = calculatePasswordStrength(this.value);
        strengthIndicator.textContent = strength.text;
        strengthIndicator.className = `password-strength strength-${strength.level}`;
      }
    });
  });

  function calculatePasswordStrength(password) {
    let score = 0;

    if (password.length >= 8) score++;
    if (password.match(/[a-z]/) && password.match(/[A-Z]/)) score++;
    if (password.match(/\d/)) score++;
    if (password.match(/[^a-zA-Z\d]/)) score++;

    const levels = [
      { level: "weak", text: "Weak password" },
      { level: "weak", text: "Weak password" },
      { level: "medium", text: "Medium strength" },
      { level: "strong", text: "Strong password" },
      { level: "strong", text: "Very strong password" },
    ];

    return levels[Math.min(score, levels.length - 1)];
  }

  // Form validation enhancements
  const forms = document.querySelectorAll("form");
  forms.forEach((form) => {
    form.addEventListener("submit", function (e) {
      const submitButton = this.querySelector('button[type="submit"]');
      if (submitButton) {
        submitButton.disabled = true;
        submitButton.innerHTML =
          '<i class="fas fa-spinner fa-spin"></i> Processing...';

        // Re-enable button after 5 seconds in case of error
        setTimeout(() => {
          submitButton.disabled = false;
          submitButton.innerHTML =
            submitButton.getAttribute("data-original-text") || "Submit";
        }, 5000);
      }
    });
  });

  // Store original button text
  document.querySelectorAll('button[type="submit"]').forEach((button) => {
    button.setAttribute("data-original-text", button.innerHTML);
  });
});
