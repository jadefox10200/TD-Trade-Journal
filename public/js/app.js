

function toFixed(x) {
  if (Math.abs(x) < 1.0) {
	var e = parseInt(x.toString().split('e-')[1]);
	if (e) {
		x *= Math.pow(10,e-1);
		x = '0.' + (new Array(e)).join('0') + x.toString().substring(2);
	}
  } else {
	var e = parseInt(x.toString().split('+')[1]);
	if (e > 20) {
		e -= 20;
		x /= Math.pow(10,e);
		x += (new Array(e+1)).join('0');
	}
  }
  return x;
}

//use this function to truncate a floating point number to a set limit defined by 'n'
function toFixedTrunc(x, n) {
  x = toFixed(x)

  // From here on the code is the same than the original answer
  const v = (typeof x === 'string' ? x : x.toString()).split('.');
  if (n <= 0) return v[0];
  let f = v[1] || '';
  if (f.length > n) return `${v[0]}.${f.substr(0,n)}`;
  while (f.length < n) f += '0';
  return `${v[0]}.${f}`
}
