/*
 * GlassShell
 * Author: XQQYT
 * License: MIT
 * Year: 2025
 */

#include "GlassShell/EventBus/EventBus.h"

EventBus EventBus::instance;

EventBus::EventBus(){
    thread_pool = std::make_unique<ThreadPool<>>(2, 4, 1024, ThreadPoolType::NORMAL);
    registerAllEvents();
    initModuleSubscribe();
};

EventBus::~EventBus(){
};

void EventBus::initModuleSubscribe()
{

}

void EventBus::registerAllEvents() {
    for (int i = 0; i < static_cast<int>(EventType::MaxEnumValue); ++i) {
        EventType evt = static_cast<EventType>(i);
        registerEvent(evt);
    }
}
