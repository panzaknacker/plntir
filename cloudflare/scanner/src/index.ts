import { assertSealedEnvironment } from "./environment";
import { loadScanJob } from "./job";
import { PermanentEventError, type R2EventNotification } from "./model";

export { ScannerContainer } from "./container";
export { ScanWorkflow } from "./workflow";

async function consumeMessage(message: Message<R2EventNotification>, environment: CloudflareBindings): Promise<void> {
  let job;
  try {
    job = await loadScanJob(message.body, environment);
  } catch (error) {
    if (error instanceof PermanentEventError) {
      console.error(
        JSON.stringify({
          event: "scan_event_rejected",
          message_id: message.id,
          reason: error.message,
        }),
      );
      message.ack();
      return;
    }
    console.error(
      JSON.stringify({
        event: "scan_event_deferred",
        message_id: message.id,
        error_type: error instanceof Error ? error.name : "unknown",
      }),
    );
    message.retry();
    return;
  }

  try {
    await environment.SCAN_WORKFLOW.create({
      id: job.jobID,
      params: job,
      retention: { successRetention: "30 days", errorRetention: "30 days" },
      locationHint: "weur",
    });
    message.ack();
  } catch (error) {
    try {
      await environment.SCAN_WORKFLOW.get(job.jobID);
      console.log(JSON.stringify({ event: "scan_workflow_duplicate", job_id: job.jobID }));
      message.ack();
    } catch {
      console.error(
        JSON.stringify({
          event: "scan_workflow_create_failed",
          job_id: job.jobID,
          error_type: error instanceof Error ? error.name : "unknown",
        }),
      );
      message.retry();
    }
  }
}

export default {
  fetch(): Response {
    return new Response("Not Found", {
      status: 404,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "text/plain; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },

  async queue(batch: MessageBatch<R2EventNotification>, environment: CloudflareBindings): Promise<void> {
    assertSealedEnvironment(environment);
    await Promise.all(batch.messages.map((message) => consumeMessage(message, environment)));
  },
} satisfies ExportedHandler<CloudflareBindings, R2EventNotification>;
