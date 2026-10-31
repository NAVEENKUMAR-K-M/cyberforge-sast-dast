<?php
class Mailer {
    private $smtpPassword = "m4il-Relay-Passw0rd";

    public function send($to, $subject) {
        return mail($to, $subject, 'Hello');
    }
}
