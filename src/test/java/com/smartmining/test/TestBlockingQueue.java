package com.smartmining.test;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

public class TestBlockingQueue {
    /**
     * 生产和消费业务操作
     * 
     * @author tang
     *
     */
    protected class WorkDesk {

        BlockingQueue<String> desk = new LinkedBlockingQueue<String>(10);

        public void washDish() throws InterruptedException {
            desk.put("洗好一个盘子");
        }

        public String useDish() throws InterruptedException {
            return desk.take();
        }
    }

    /**
     * 生产者类
     * 
     * @author tang
     *
     */
    class Producer implements Runnable {

        private String producerName;
        private WorkDesk workDesk;

        public Producer(String producerName, WorkDesk workDesk) {
            this.producerName = producerName;
            this.workDesk = workDesk;
        }

        @Override
        public void run() {
            try {
                for (;;) {
                    System.out.println(producerName + "洗好一个盘子");
                    workDesk.washDish();
                    Thread.sleep(1000);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 消费者类
     * 
     * @author tang
     *
     */
    class Consumer implements Runnable {
        private String consumerName;
        private WorkDesk workDesk;

        public Consumer(String consumerName, WorkDesk workDesk) {
            this.consumerName = consumerName;
            this.workDesk = workDesk;
        }

        @Override
        public void run() {
            try {
                for (;;) {
                    System.out.println(consumerName + "使用一个盘子");
                    workDesk.useDish();
                    Thread.sleep(1000);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String args[]) throws InterruptedException {
        TestBlockingQueue testQueue = new TestBlockingQueue();
        WorkDesk workDesk = testQueue.new WorkDesk();

        ExecutorService service = Executors.newCachedThreadPool();
        //四个生产者线程
        Producer producer1 = testQueue.new Producer("生产者-1-", workDesk);
        Producer producer2 = testQueue.new Producer("生产者-2-", workDesk);
        Producer producer3 = testQueue.new Producer("生产者-3-", workDesk);
        Producer producer4 = testQueue.new Producer("生产者-4-", workDesk);
        //两个消费者线程
        Consumer consumer1 = testQueue.new Consumer("消费者-1-", workDesk);
        Consumer consumer2 = testQueue.new Consumer("消费者-2-", workDesk);
        
        service.submit(producer1);
        service.submit(producer2);
        service.submit(producer3);
        service.submit(producer4);
        service.submit(consumer1);
        service.submit(consumer2);

    }

}