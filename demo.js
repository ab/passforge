/*
 * Javascript to power the HTML PassForge interface.
 */

function toggle_progress(elem) {
  var progress = document.getElementById('progressContainer');
  if (elem.checked) {
    //progress.style.visibility = "visible";
    progress.style.display = "block";
  } else {
    //progress.style.visibility = "hidden";
    progress.style.display = "none";
  }
}

function set_progress(out_of_100) {
  var progress = document.getElementById('progress');
  progress.style.width = out_of_100 + "%";
}

function set_iters(elem) {
  var iters = document.getElementById('iterations')
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

var status_callback = function(fraction_done) {
  set_progress(fraction_done * 100);
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
    passforge.config(form.length.value, form.iterations.value,
                     status_callback, result_callback);
  } catch(e) {
    button.classList.remove('disabled');
    alert('ERROR: ' + e.message);
    return;
  }

  // show result input
  document.getElementById('key').style.display = '';

  var async = true;
  if (form.progress) {
      async = form.progress.checked;
  }

  passforge.pwgen(form.password.value, form.nickname.value, async);
}

/* vim: set ts=2 sw=2 : */
