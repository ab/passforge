/*
 * Javascript to power the HTML PassForge interface.
 */

current_progress = 0;
function set_progress(out_of_100) {
  current_progress = out_of_100;
  var progress = document.getElementById('progress');
  progress.style.width = out_of_100 + "%";
}

function set_iters(elem) {
  var iters = document.getElementById('rounds')
  if (elem.value == 'custom') {
    if (!iters.disabled) {
      return;
    }
    iters.disabled = false;
    iters.focus();
    iters.select();
  } else {
    iters.disabled = true;
    iters.value = elem.value;
  }
}

var status_callback = function() {
  current_progress += 1;
  set_progress(current_progress);
};

var result_callback = function(key, elapsed) {
  set_progress(100);
  var text = "created in " + elapsed + "s";
  document.getElementById("time").innerHTML = text;

  var keyInput = document.getElementById('key');
  keyInput.value = key;
  keyInput.focus();
  keyInput.select();

  document.getElementById('startButton').classList.remove('disabled');
  set_progress(0);
};

function clear_validation_errors() {
  var form = document.getElementById('demoForm');

  form.password.parentNode.classList.remove('error');
  form.nickname.parentNode.classList.remove('error');
}

function generate() {
  var button = document.getElementById('startButton');
  var form = document.getElementById('demoForm');

  // do nothing if generation is already running
  if (button.classList.contains('disabled')) {
    return false;
  }

  clear_validation_errors();

  var validation_errors = false;
  // validation error if password or nickname is blank
  if (!form.password.value) {
    form.password.parentNode.classList.add('error');
    validation_errors = true;
  }
  if (!form.nickname.value) {
    form.nickname.parentNode.classList.add('error');
    validation_errors = true;
  }
  if (validation_errors) {
    return true;
  }

  button.classList.add('disabled');

  try {
    passforge.config(result_callback, status_callback);
  } catch(e) {
    button.classList.remove('disabled');
    alert('ERROR: ' + e.message);
    return;
  }

  // show result input
  document.getElementById('key').style.display = '';

  try {
    passforge.generate(form.password.value, form.nickname.value,
                       form.rounds.value, form.length.value);
  } catch(e) {
    button.classList.remove('disabled');
    alert('ERROR: ' + e.message);
    return;
  }
}

/* vim: set ts=2 sw=2 : */
