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

use App\Services\InboundMail\InboundMailEngine;
use App\Utils\Ninja;
use App\Models\Company;
use App\Libraries\MultiDB;
use Illuminate\Http\Request;
use App\Utils\Traits\SavesDocuments;
use App\Jobs\Mailgun\ProcessMailgunWebhook;
use App\Jobs\Mailgun\ProcessMailgunInboundWebhook;

/**
 * Class MailgunController.
 */
class MailgunController extends BaseController
{
    use SavesDocuments;

    public function __construct() {}

    /**
     * Process Mailgun Webhook.
     *
     *
     * @OA\Post(
     *      path="/api/v1/mailgun_webhook",
     *      operationId="mailgunWebhook",
     *      tags={"mailgun"},
     *      summary="Processing webhooks from Mailgun",
     *      description="Adds an credit to the system",
     *      @OA\Parameter(ref="#/components/parameters/X-API-TOKEN"),
     *      @OA\Parameter(ref="#/components/parameters/X-Requested-With"),
     *      @OA\Parameter(ref="#/components/parameters/include"),
     *      @OA\Response(
     *          response=200,
     *          description="Returns the saved credit object",
     *          @OA\Header(header="X-MINIMUM-CLIENT-VERSION", ref="#/components/headers/X-MINIMUM-CLIENT-VERSION"),
     *          @OA\Header(header="X-RateLimit-Remaining", ref="#/components/headers/X-RateLimit-Remaining"),
     *          @OA\Header(header="X-RateLimit-Limit", ref="#/components/headers/X-RateLimit-Limit"),
     *          @OA\JsonContent(ref="#/components/schemas/Credit"),
     *       ),
     *       @OA\Response(
     *          response=422,
     *          description="Validation error",
     *          @OA\JsonContent(ref="#/components/schemas/ValidationError"),
     *
     *       ),
     *       @OA\Response(
     *           response="default",
     *           description="Unexpected Error",
     *           @OA\JsonContent(ref="#/components/schemas/Error"),
     *       ),
     *     )
     */
    public function webhook(Request $request)
    {

        $input = $request->all();

        // TEMPORARY diagnostic logging while chasing down why webhooks weren't
        // resulting in ProcessMailgunWebhook being dispatched. Remove once
        // confirmed working — nothing here changes the response Mailgun sees.
        nlog('Mailgun webhook received', [
            'content_type' => $request->header('Content-Type'),
            'top_level_keys' => array_keys($input),
            'event' => $input['event-data']['event'] ?? null,
            'has_signature_block' => isset($input['signature']),
            'signing_key_configured' => strlen((string) config('services.mailgun.webhook_signing_key')) > 0,
        ]);

        if (!isset($input['signature']['timestamp'], $input['signature']['token'], $input['signature']['signature'])) {
            nlog('Mailgun webhook rejected: no signature block in payload', ['input' => $input]);
            return response()->json(['message' => 'Success'], 200);
        }

        $age = \abs(\time() - (int) $input['signature']['timestamp']);

        if ($age > 15) {
            nlog('Mailgun webhook rejected: timestamp outside 15s tolerance', [
                'age_seconds' => $age,
                'payload_timestamp' => $input['signature']['timestamp'],
                'server_time' => \time(),
            ]);
            return response()->json(['message' => 'Success'], 200);
        }

        $expected = \hash_hmac('sha256', $input['signature']['timestamp'] . $input['signature']['token'], config('services.mailgun.webhook_signing_key'));
        $matches = \hash_equals($expected, $input['signature']['signature']);

        nlog('Mailgun webhook signature check', ['matches' => $matches]);

        if ($matches) {
            ProcessMailgunWebhook::dispatch($request->all())->delay(rand(2, 10));
        }

        return response()->json(['message' => 'Success.'], 200);
    }

    /**
     * Process Mailgun Inbound Webhook.
     *
     * IMPORTANT NOTICE: mailgun does NOT strip old sended emails, therefore all past attachements are present
     *
     * IMPORTANT NOTICE: mailgun saves the message and attachemnts for later retrieval, therefore we can process it within a async job for performance reasons
     *
     *
     * @OA\Post(
     *      path="/api/v1/mailgun_inbound_webhook",
     *      operationId="mailgunInboundWebhook",
     *      tags={"mailgun"},
     *      summary="Processing inbound webhooks from Mailgun",
     *      description="Adds an credit to the system",
     *      @OA\Parameter(ref="#/components/parameters/X-API-TOKEN"),
     *      @OA\Parameter(ref="#/components/parameters/X-Requested-With"),
     *      @OA\Parameter(ref="#/components/parameters/include"),
     *      @OA\Response(
     *          response=200,
     *          description="Returns the saved credit object",
     *          @OA\Header(header="X-MINIMUM-CLIENT-VERSION", ref="#/components/headers/X-MINIMUM-CLIENT-VERSION"),
     *          @OA\Header(header="X-RateLimit-Remaining", ref="#/components/headers/X-RateLimit-Remaining"),
     *          @OA\Header(header="X-RateLimit-Limit", ref="#/components/headers/X-RateLimit-Limit"),
     *          @OA\JsonContent(ref="#/components/schemas/Credit"),
     *       ),
     *       @OA\Response(
     *          response=422,
     *          description="Validation error",
     *          @OA\JsonContent(ref="#/components/schemas/ValidationError"),
     *
     *       ),
     *       @OA\Response(
     *           response="default",
     *           description="Unexpected Error",
     *           @OA\JsonContent(ref="#/components/schemas/Error"),
     *       ),
     *     )
     */
    public function inboundWebhook(Request $request)
    {
        $input = $request->all();

        $authorizedByHash = \hash_equals(\hash_hmac('sha256', $input['timestamp'] . $input['token'], config('services.mailgun.webhook_signing_key')), $input['signature']);
        $authorizedByToken = $request->has('token') && $request->get('token') == config('ninja.inbound_mailbox.inbound_webhook_token');
        if (!$authorizedByHash && !$authorizedByToken) {
            return response()->json(['message' => 'Unauthorized'], 403);
        }

        nlog($input);

        if (!array_key_exists('sender', $input) || !array_key_exists('recipient', $input) || !array_key_exists('message-url', $input)) {
            nlog('Failed: Message could not be parsed, because required parameters are missing. Please ensure contacting this api-endpoint with a store & notify operation instead of a forward operation!');
            return response()->json(['message' => 'Failed. Missing Parameters. Use store and notify!'], 400);
        }

        $inboundEngine = new InboundMailEngine();

        // Spam protection
        if ($inboundEngine->isInvalidOrBlocked($input["sender"], $input["recipient"])) {
            return;
        }

        // Dispatch Job for processing
        ProcessMailgunInboundWebhook::dispatch($input["sender"], $input["recipient"], $input["message-url"])->delay(rand(2, 10));

        return response()->json(['message' => 'Success.'], 200);
    }
}
