// Builds a plain-text alert email as raw MIME, for the send_email binding.
// Kept free of Workers-only imports so the tests can run it under node.

const b64 = (s) => {
	const bytes = new TextEncoder().encode(s);
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
};

const oneLine = (s) => String(s).replace(/[\r\n]+/g, " ").trim();

export function alertMime({ from, to, subject, body, date = new Date(), id = crypto.randomUUID() }) {
	const domain = from.split("@")[1];
	return [
		`From: tattle <${oneLine(from)}>`,
		`To: ${oneLine(to)}`,
		`Subject: =?UTF-8?B?${b64(oneLine(subject).slice(0, 200))}?=`,
		`Date: ${date.toUTCString()}`,
		`Message-ID: <${id}@${domain}>`,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: base64",
		"",
		b64(body).replace(/.{76}/g, "$&\r\n"),
		"",
	].join("\r\n");
}
