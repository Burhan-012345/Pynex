document.addEventListener("DOMContentLoaded", function () {
  // Enhanced toggle password visibility
  const toggleButtons = document.querySelectorAll(".toggle-password");

  toggleButtons.forEach((button) => {
    button.addEventListener("click", function () {
      // Find the associated password input
      const passwordInput =
        this.closest(".password-input-container")?.querySelector(
          'input[type="password"], input[type="text"]'
        ) || this.previousElementSibling;

      if (!passwordInput) return;

      const type =
        passwordInput.getAttribute("type") === "password" ? "text" : "password";
      passwordInput.setAttribute("type", type);

      // Toggle eye icon with better accessibility
      const icon = this.querySelector("i");
      if (icon) {
        if (type === "password") {
          icon.className = "fas fa-eye";
          this.setAttribute("aria-label", "Show password");
        } else {
          icon.className = "fas fa-eye-slash";
          this.setAttribute("aria-label", "Hide password");
        }
      }

      // Focus back on the password input for better UX
      passwordInput.focus();
    });

    // Add keyboard support for accessibility
    button.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        this.click();
      }
    });
  });

  // Enhanced password strength indicator
  const passwordInputs = document.querySelectorAll('input[type="password"]');

  passwordInputs.forEach((input) => {
    // Add event listener for input changes
    input.addEventListener("input", function () {
      updatePasswordStrength(this);
    });

    // Initialize strength indicator if it exists
    updatePasswordStrength(input);
  });

  function updatePasswordStrength(input) {
    const strengthIndicator =
      input.parentNode.querySelector(".password-strength");
    const strengthMeter = input.parentNode.querySelector(".strength-fill");
    const strengthText = input.parentNode.querySelector(".strength-text");

    if (strengthIndicator || strengthMeter) {
      const strength = calculatePasswordStrength(input.value);

      if (strengthIndicator) {
        strengthIndicator.textContent = strength.text;
        strengthIndicator.className = `password-strength strength-${strength.level}`;
      }

      if (strengthMeter && strengthText) {
        strengthMeter.style.width = strength.width;
        strengthMeter.className = `strength-fill ${strength.class}`;
        strengthText.textContent = strength.text;
      }
    }
  }

  function calculatePasswordStrength(password) {
    let score = 0;
    const requirements = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
    };

    // Calculate score based on requirements
    if (requirements.length) score += 1;
    if (requirements.lowercase) score += 1;
    if (requirements.uppercase) score += 1;
    if (requirements.number) score += 1;
    if (requirements.special) score += 1;

    // Additional points for length
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;

    // Determine level and text with more detailed information
    const levels = [
      { level: 0, text: "Very Weak", width: "20%", class: "strength-weak" },
      { level: 1, text: "Weak", width: "40%", class: "strength-weak" },
      { level: 2, text: "Fair", width: "60%", class: "strength-fair" },
      { level: 3, text: "Good", width: "75%", class: "strength-good" },
      { level: 4, text: "Strong", width: "90%", class: "strength-strong" },
      {
        level: 5,
        text: "Very Strong",
        width: "100%",
        class: "strength-very-strong",
      },
    ];

    const levelIndex = Math.min(score, levels.length - 1);
    return levels[levelIndex];
  }

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
              ?.dispatchEvent(new Event("submit"));
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

  // Enhanced form validation with password strength check
  const forms = document.querySelectorAll("form");
  forms.forEach((form) => {
    form.addEventListener("submit", function (e) {
      // Check password strength before submission if it's a registration form
      const passwordInput = this.querySelector('input[type="password"]');
      if (passwordInput && this.id === "registerForm") {
        const strength = calculatePasswordStrength(passwordInput.value);
        if (strength.level < 2) {
          // Weak or Very Weak
          e.preventDefault();
          alert(
            "Please use a stronger password. Your password should be at least 'Fair' strength."
          );
          passwordInput.focus();
          return;
        }
      }

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

  // Add CSS for password strength indicators if not already present
  if (!document.querySelector("#password-strength-styles")) {
    const styles = document.createElement("style");
    styles.id = "password-strength-styles";
    styles.textContent = `
      .password-strength {
        font-size: 12px;
        margin-top: 5px;
        font-weight: 500;
      }
      .strength-weak { color: #dc3545; }
      .strength-fair { color: #fd7e14; }
      .strength-good { color: #ffc107; }
      .strength-strong { color: #28a745; }
      .strength-very-strong { color: #20c997; }
      
      .strength-fill {
        height: 100%;
        width: 0%;
        transition: all 0.3s ease;
        border-radius: 3px;
      }
      .strength-weak { background-color: #dc3545; }
      .strength-fair { background-color: #fd7e14; }
      .strength-good { background-color: #ffc107; }
      .strength-strong { background-color: #28a745; }
      .strength-very-strong { background-color: #20c997; }
    `;
    document.head.appendChild(styles);
  }
});
