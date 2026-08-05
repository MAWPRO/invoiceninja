<?php

/**
 * Invoice Ninja (https://invoiceninja.com).
 *
 * @link https://github.com/invoiceninja/invoiceninja source repository
 *
 * @copyright Copyright (c) 2026. Invoice Ninja LLC (https://invoiceninja.com)
 *
 * @license https://www.elastic.co/licensing/elastic-license
 */

namespace App\Http\Controllers;

use App\Http\Requests\EmailProvider\CheckEmailProviderRequest;
use App\Mail\TestMailServer;
use Illuminate\Support\Facades\Mail;

/**
 * Lets the Email Settings page ("Test") verify a mail provider actually
 * works before the user finds out the hard way when a real invoice email
 * silently fails. Mirrors the exact mailer setup NinjaMailerJob uses for
 * real sends (same Mailer::macro helpers registered in AppServiceProvider),
 * so a pass here means a real send will behave the same way.
 *
 * SmtpController::check() already covers the 'smtp' method — this covers
 * the client-supplied API-key providers (Mailgun, Postmark, Brevo, SES)
 * plus 'default', which is what actually needs testing when the mailer is
 * configured at the server/.env level (MAIL_MAILER=...) rather than per
 * company.
 */
class EmailProviderController extends BaseController
{
    private const CHECK_TIMEOUT = 5;

    public function __construct()
    {
        parent::__construct();
    }

    public function check(CheckEmailProviderRequest $request)
    {
        $startedAt = microtime(true);

        /** @var \App\Models\User $user */
        $user = auth()->user();
        $company = $user->company();
        $settings = $company->settings;

        $method = $request->input('email_sending_method');

        $sending_email = (isset($settings->custom_sending_email) && stripos($settings->custom_sending_email, '@'))
            ? $settings->custom_sending_email
            : $user->email;

        $sending_name = (isset($settings->email_from_name) && strlen($settings->email_from_name) > 2)
            ? $settings->email_from_name
            : $user->name();

        $failed = false;
        $errorMessage = null;
        $secretsToRedact = [];

        try {
            $mailable = new TestMailServer('Email Server Works!', $sending_email);
            $mailable->from($sending_email, $sending_name);

            switch ($method) {
                case 'client_mailgun':
                    $secret = (string) $request->input('mailgun_secret');
                    $domain = (string) $request->input('mailgun_domain');
                    $endpoint = (string) $request->input('mailgun_endpoint', 'api.mailgun.net');
                    $secretsToRedact = [$secret];

                    Mail::mailer('mailgun')
                        ->mailgun_config($secret, $domain, $endpoint)
                        ->to($user->email, $user->present()->name())
                        ->send($mailable);
                    break;

                case 'client_postmark':
                    $secret = (string) $request->input('postmark_secret');
                    $secretsToRedact = [$secret];

                    Mail::mailer('postmark')
                        ->postmark_config($secret)
                        ->to($user->email, $user->present()->name())
                        ->send($mailable);
                    break;

                case 'client_brevo':
                    $secret = (string) $request->input('brevo_secret');
                    $secretsToRedact = [$secret];

                    Mail::mailer('brevo')
                        ->brevo_config($secret)
                        ->to($user->email, $user->present()->name())
                        ->send($mailable);
                    break;

                case 'client_ses':
                    $access_key = (string) $request->input('ses_access_key');
                    $secret_key = (string) $request->input('ses_secret_key');
                    $region = (string) $request->input('ses_region', 'us-east-1');
                    $topic_arn = $request->input('ses_topic_arn') ?: null;
                    $secretsToRedact = [$access_key, $secret_key];

                    Mail::mailer('ses')
                        ->ses_config($access_key, $secret_key, $region ?: 'us-east-1', $topic_arn)
                        ->to($user->email, $user->present()->name())
                        ->send($mailable);
                    break;

                default:
                    // 'default': whatever MAIL_MAILER=... in .env resolves to — no
                    // client-supplied secret involved, so nothing to redact.
                    Mail::mailer(config('mail.default'))
                        ->to($user->email, $user->present()->name())
                        ->send($mailable);
                    break;
            }
        } catch (\Throwable $e) {
            nlog('Email provider check failed', [
                'company_id' => $company->id ?? null,
                'method' => $method,
                'error' => $e->getMessage(),
            ]);

            $failed = true;
            $errorMessage = $this->redact($e->getMessage(), $secretsToRedact);
        }

        app('mail.manager')->forgetMailers();

        $this->padResponse($startedAt);

        if ($failed) {
            return response()->json([
                'message' => $errorMessage ?: 'Could not send a test email with these settings.',
            ], 400);
        }

        return response()->json(['message' => 'Ok, test email sent — check your inbox.'], 200);
    }

    /**
     * Strips any client-supplied secret out of an exception message before it
     * goes back to the browser. Provider error bodies don't normally echo the
     * key back, but this is cheap insurance against a provider that does.
     *
     * @param  string[] $secrets
     */
    private function redact(string $message, array $secrets): string
    {
        foreach (array_filter($secrets) as $secret) {
            if (strlen($secret) >= 6) {
                $message = str_replace($secret, '[redacted]', $message);
            }
        }

        return $message;
    }

    /**
     * Provide a constant delay to avoid timing oracles.
     */
    private function padResponse(float $startedAt): void
    {
        $elapsed = microtime(true) - $startedAt;
        $remaining = self::CHECK_TIMEOUT - $elapsed;

        if ($remaining > 0) {
            usleep((int) ($remaining * 1_000_000));
        }
    }
}
