#include "include/WorkerThread.h"
#include <iostream>

SubframeWorkerThread::SubframeWorkerThread(ThreadSafeQueue<SubframeWorker>& avail,
                                           ThreadSafeQueue<SubframeWorker>& pending) :
  thread("workerthread"),
  avail(avail),
  pending(pending),
  canceled(false),
  joined(false)
{

}

SubframeWorkerThread::~SubframeWorkerThread() {
  cancel();
  wait_thread_finish();
}

void SubframeWorkerThread::cancel() {
  // this function must not block!
  canceled.store(true);
}

void SubframeWorkerThread::wait_thread_finish() {
  std::lock_guard<std::mutex> lock(join_mutex);
  if(!joined) {
    thread::wait_thread_finish();
    joined = true;
  }
}

void SubframeWorkerThread::run_thread() {
  //std::cout << "SubframeWorkerThread ready" << std::endl;
  while(!canceled.load()) {
    std::shared_ptr<SubframeWorker> worker = pending.dequeue();
    if(worker != nullptr) {
      worker->work();
      // enqueue finished worker
      avail.enqueue(std::move(worker));
    }
    else {
      // nullptr is only returned if phy is canceled
      canceled.store(true);
    }
  }
  //std::cout << "SubframeWorkerThread ended" << std::endl;
}

SnifferThread::SnifferThread(ThreadSafeQueue<SubframeWorker>& avail,
                             ThreadSafeQueue<SubframeWorker>& pending,
                             std::future<void>              & thread_return):
  avail(avail),
  pending(pending),
  canceled(false),
  joined(false)
  // thread_return(thread_return)
{

}

SnifferThread::~SnifferThread() {
  cancel();
  wait_thread_finish();
}

void SnifferThread::cancel() {
  // this function must not block!
  canceled.store(true);
}

void SnifferThread::wait_thread_finish() {
  std::lock_guard<std::mutex> lock(join_mutex);
  if(!joined) {
    if(thread_return.valid()) {
      thread_return.wait();
    }
    joined = true;
  }
}

void SnifferThread::execute_worker(){
  while(!canceled.load()) {
    std::shared_ptr<SubframeWorker> worker = pending.dequeue();
    if(worker != nullptr) {
      worker->work();
      // enqueue finished worker
      avail.enqueue(std::move(worker));
    }
    else {
      // nullptr is only returned if phy is canceled
      canceled.store(true);
    }
  }
}

void SnifferThread::run_thread() {
  /*create a new async thread to execute subframe worker*/
  thread_return = async(std::launch::async, [this]{ this->execute_worker();});
}
