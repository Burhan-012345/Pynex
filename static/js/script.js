// Expense form handling
document.addEventListener("DOMContentLoaded", function () {
  const expenseForm = document.getElementById("expenseForm");
  const expensesList = document.getElementById("expensesList");

  if (expenseForm) {
    expenseForm.addEventListener("submit", async function (e) {
      e.preventDefault();

      const submitButton = this.querySelector('button[type="submit"]');
      const originalText = submitButton.innerHTML;

      try {
        submitButton.disabled = true;
        submitButton.innerHTML =
          '<i class="fas fa-spinner fa-spin"></i> Adding...';

        const formData = new FormData(this);
        const data = {
          amount: parseFloat(formData.get("amount")),
          category: formData.get("category"),
          description: formData.get("description"),
          date: formData.get("date"),
        };

        // Validation
        if (data.amount <= 0) {
          throw new Error("Amount must be greater than 0");
        }

        if (!data.category) {
          throw new Error("Please select a category");
        }

        const response = await fetch("/add-expense", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(data),
        });

        const result = await response.json();

        if (response.ok) {
          showNotification("Expense added successfully!", "success");
          this.reset();

          // Set default date to today
          const today = new Date().toISOString().split("T")[0];
          document.getElementById("date").value = today;

          // Reload expenses if on dashboard
          if (typeof loadExpenses === "function") {
            loadExpenses();
          }

          // Reload recent expenses if on add expense page
          if (typeof loadRecentExpenses === "function") {
            loadRecentExpenses();
          }
        } else {
          throw new Error(result.error);
        }
      } catch (error) {
        showNotification("Error: " + error.message, "error");
      } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
      }
    });
  }

  // Load expenses for dashboard
  async function loadExpenses() {
    try {
      const response = await fetch("/get-expenses?limit=5");
      const expenses = await response.json();

      if (expensesList) {
        expensesList.innerHTML = "";

        if (expenses.length === 0) {
          expensesList.innerHTML = `
                        <div style="text-align: center; padding: 40px; color: #6c757d;">
                            <i class="fas fa-receipt fa-3x" style="margin-bottom: 15px;"></i>
                            <p>No expenses recorded yet.</p>
                            <p>Start by adding your first expense above!</p>
                        </div>
                    `;
          return;
        }

        expenses.forEach((expense) => {
          const expenseElement = document.createElement("div");
          expenseElement.className = "expense-item";
          expenseElement.innerHTML = `
                        <div>
                            <strong>${formatCurrencySimple(
                              expense.amount
                            )}</strong>
                            <span class="expense-category expense-${expense.category.toLowerCase()}">${
            expense.category
          }</span>
                            <div>${
                              expense.description || "No description"
                            }</div>
                            <small>${expense.date}</small>
                        </div>
                        <button class="delete-btn" onclick="deleteExpense('${
                          expense.id
                        }')">
                            <i class="fas fa-trash"></i>
                        </button>
                    `;
          expensesList.appendChild(expenseElement);
        });
      }
    } catch (error) {
      console.error("Error loading expenses:", error);
      showNotification("Error loading expenses: " + error.message, "error");
    }
  }

  // Initial load for dashboard
  if (expensesList) {
    loadExpenses();
  }
});

// Delete expense function
async function deleteExpense(expenseId) {
  if (
    !confirm(
      "Are you sure you want to delete this expense? This action cannot be undone."
    )
  ) {
    return;
  }

  try {
    const response = await fetch(`/delete-expense/${expenseId}`, {
      method: "DELETE",
    });

    const result = await response.json();

    if (response.ok) {
      showNotification("Expense deleted successfully!", "success");
      // Reload the current page
      setTimeout(() => {
        location.reload();
      }, 1000);
    } else {
      throw new Error(result.error);
    }
  } catch (error) {
    showNotification("Error deleting expense: " + error.message, "error");
  }
}

// Auth form handling
function handleAuthForm(formId, endpoint, successRedirect) {
  const form = document.getElementById(formId);
  if (form) {
    form.addEventListener("submit", async function (e) {
      e.preventDefault();

      const submitButton = this.querySelector('button[type="submit"]');
      const originalText = submitButton.innerHTML;

      try {
        submitButton.disabled = true;
        submitButton.innerHTML =
          '<i class="fas fa-spinner fa-spin"></i> Processing...';

        const formData = new FormData(this);
        const data = Object.fromEntries(formData);

        // Additional validation
        if (
          data.new_password &&
          data.confirm_password &&
          data.new_password !== data.confirm_password
        ) {
          throw new Error("Passwords do not match");
        }

        const response = await fetch(endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(data),
        });

        const result = await response.json();

        if (response.ok) {
          showNotification(result.message, "success");

          if (successRedirect) {
            setTimeout(() => {
              window.location.href = successRedirect;
            }, 1500);
          } else if (result.redirect) {
            setTimeout(() => {
              window.location.href = result.redirect;
            }, 1500);
          } else {
            // For OTP verification, redirect to next step
            if (formId === "verifyOtpForm") {
              const purpose = data.purpose;
              if (purpose === "register") {
                setTimeout(() => {
                  window.location.href = "/login-page";
                }, 1500);
              } else if (purpose === "reset") {
                setTimeout(() => {
                  window.location.href = "/reset-password-page";
                }, 1500);
              }
            }
          }
        } else {
          throw new Error(result.error);
        }
      } catch (error) {
        showNotification(error.message, "error");
      } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
      }
    });
  }
}

// Notification system
function showNotification(message, type = "info") {
  // Remove existing notifications
  const existingNotifications = document.querySelectorAll(".notification");
  existingNotifications.forEach((notification) => notification.remove());

  const notification = document.createElement("div");
  notification.className = `notification notification-${type}`;
  notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${getNotificationIcon(type)}"></i>
            <span>${message}</span>
        </div>
        <button class="notification-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;

  document.body.appendChild(notification);

  // Add styles if not already added
  if (!document.querySelector("#notification-styles")) {
    const styles = document.createElement("style");
    styles.id = "notification-styles";
    styles.textContent = `
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                background: white;
                border-radius: 10px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                padding: 15px 20px;
                min-width: 300px;
                max-width: 500px;
                z-index: 10000;
                display: flex;
                align-items: center;
                justify-content: space-between;
                border-left: 4px solid #4361ee;
                animation: slideInRight 0.3s ease;
            }
            
            .notification-success {
                border-left-color: #4cc9f0;
            }
            
            .notification-error {
                border-left-color: #f72585;
            }
            
            .notification-info {
                border-left-color: #4361ee;
            }
            
            .notification-content {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .notification-close {
                background: none;
                border: none;
                color: #6c757d;
                cursor: pointer;
                padding: 5px;
            }
            
            @keyframes slideInRight {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
        `;
    document.head.appendChild(styles);
  }

  // Auto remove after 5 seconds
  setTimeout(() => {
    if (notification.parentElement) {
      notification.remove();
    }
  }, 5000);
}

function getNotificationIcon(type) {
  const icons = {
    success: "check-circle",
    error: "exclamation-circle",
    info: "info-circle",
    warning: "exclamation-triangle",
  };
  return icons[type] || "info-circle";
}

// Initialize auth forms
document.addEventListener("DOMContentLoaded", function () {
  handleAuthForm("loginForm", "/auth/login", "/dashboard");
  handleAuthForm("registerForm", "/auth/register");
  handleAuthForm("forgotPasswordForm", "/auth/forgot-password");
  handleAuthForm("verifyOtpForm", "/auth/verify-otp");
  handleAuthForm("resetPasswordForm", "/auth/reset-password", "/login-page");

  // Add input validation indicators
  const inputs = document.querySelectorAll(
    "input[required], select[required], textarea[required]"
  );
  inputs.forEach((input) => {
    input.addEventListener("blur", function () {
      if (!this.value) {
        this.style.borderColor = "#f72585";
      } else {
        this.style.borderColor = "#4cc9f0";
      }
    });

    input.addEventListener("input", function () {
      if (this.value) {
        this.style.borderColor = "#4cc9f0";
      }
    });
  });
});

// Utility functions
function formatCurrency(amount) {
  return new Intl.NumberFormat("en-IN", {
    style: "currency",
    currency: "INR",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(amount);
}

function formatCurrencySimple(amount) {
  return "₹" + parseFloat(amount).toFixed(2);
}

function formatDate(dateString) {
  return new Date(dateString).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

// Export functions for global access
window.deleteExpense = deleteExpense;
window.showNotification = showNotification;
window.formatCurrencySimple = formatCurrencySimple;
