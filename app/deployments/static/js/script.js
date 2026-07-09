// Toggles visibility of dependent form fields
function hideOrShow(el) {
  var fname = hideOrShow.name.toLowerCase();
  var selector = $(el).data(fname + '-selector');
  var search_id = '[' + selector + ']';

  var pattern = $(el).data(fname + '-' + el.value.toString() + '-pattern');
  var re = new RegExp(pattern);

  $(search_id).each(function () {
    if (this.id !== el.id){
      $(this).parent().closest('div').attr('hidden', true);

      if ( re.test(this.id) ) {
        $(this).parent().closest('div').attr('hidden', false);
      }
    }
  });
};

// Check password double time.
var SECRET_MIN_LENGTH = 8;
// letters, digits and a restricted set of "safe" special characters
// excluded: ' " ` \ $ ; | & < > ( ) { } [ ] spaces and newlines
var SECRET_ALLOWED_PATTERN = /^[A-Za-z0-9!@#%^*_+=.,:-]+$/;

function validateSecretValue(input, msgEl) {
  var value = input.value;

  if (!value) {
    return null; // empty field, handled elsewhere (required)
  }
  if (value.length < SECRET_MIN_LENGTH) {
    return 'Password must be at least ' + SECRET_MIN_LENGTH + ' characters.';
  }
  if (!SECRET_ALLOWED_PATTERN.test(value)) {
    return "Only letters, numbers and these special characters are allowed: ! @ # % ^ * _ + = . , : -";
  }
  return null; // valid
}

function checkSecretMatch(baseInput) {
  var confirmInput = document.getElementById(baseInput.id + '_confirm');
  var msg = document.getElementById(baseInput.id + '_match_msg');
  if (!confirmInput || !msg) return true;

  // 1. validate the main field (length + allowed characters)
  var baseError = validateSecretValue(baseInput, msg);
  if (baseError) {
    msg.textContent = baseError;
    msg.classList.add('text-danger');
    baseInput.classList.add('is-invalid');
    baseInput.setCustomValidity(baseError);
    confirmInput.classList.remove('is-valid', 'is-invalid');
    return false;
  }
  baseInput.classList.remove('is-invalid');
  baseInput.setCustomValidity('');

  // 2. if confirm field is empty, no error yet
  if (!confirmInput.value) {
    msg.textContent = '';
    confirmInput.classList.remove('is-valid', 'is-invalid');
    confirmInput.setCustomValidity('');
    return true;
  }

  // 3. validate the confirm field too (same constraints)
  var confirmError = validateSecretValue(confirmInput, msg);
  if (confirmError) {
    msg.textContent = confirmError;
    msg.classList.add('text-danger');
    confirmInput.classList.remove('is-valid');
    confirmInput.classList.add('is-invalid');
    confirmInput.setCustomValidity(confirmError);
    return false;
  }

  // 4. finally check that both values match
  if (baseInput.value !== confirmInput.value) {
    msg.textContent = 'Passwords do not match.';
    msg.classList.add('text-danger');
    confirmInput.classList.remove('is-valid');
    confirmInput.classList.add('is-invalid');
    confirmInput.setCustomValidity('Passwords do not match.');
    return false;
  }

  msg.textContent = 'Passwords match.';
  msg.classList.remove('text-danger');
  confirmInput.classList.remove('is-invalid');
  confirmInput.classList.add('is-valid');
  confirmInput.setCustomValidity('');
  return true;
}

// live validation while the user types
$(document).on('input', 'input[data-type="secret"]', function () {
  var id = this.id.endsWith('_confirm') ? this.id.replace('_confirm', '') : this.id;
  var baseInput = document.getElementById(id);
  if (baseInput) checkSecretMatch(baseInput);
});

// block form submit if any secret/confirm pair is invalid or doesn't match
$(document).on('submit', 'form', function (e) {
  var allValid = true;

  $('input[data-type="secret"]').each(function () {
    if (this.id.endsWith('_confirm')) return; // only check from the main field
    if (!checkSecretMatch(this)) {
      allValid = false;
    }
  });

  if (!allValid) {
    e.preventDefault();
  }
});
