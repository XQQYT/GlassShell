/*
 * GlassShell
 * Author: XQQYT
 * License: MIT
 * Year: 2025
 */

#ifndef _EVENTBUS_H
#define _EVENTBUS_H

#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <iostream>
#include <any>
#include <atomic>
#include <memory>
#include <type_traits>

#include "GlassShell/EventBus/ThreadPool/ThreadPool.hpp"

// function_traits definition
template<typename T>
struct function_traits;

// normal function
template<typename Ret, typename... Args>
struct function_traits<Ret(Args...)> {
    using signature = Ret(Args...);
};

// function pointer
template<typename Ret, typename... Args>
struct function_traits<Ret(*)(Args...)> : function_traits<Ret(Args...)> {};

// std::function
template<typename Ret, typename... Args>
struct function_traits<std::function<Ret(Args...)>> : function_traits<Ret(Args...)> {};

// class member function pointer
template<typename ClassType, typename Ret, typename... Args>
struct function_traits<Ret(ClassType::*)(Args...)> : function_traits<Ret(Args...)> {};

// const Class member funcion pointer
template<typename ClassType, typename Ret, typename... Args>
struct function_traits<Ret(ClassType::*)(Args...) const> : function_traits<Ret(Args...)> {};

// function object（include lambda）
template<typename Callable>
struct function_traits : function_traits<decltype(&Callable::operator())> {};

// specialize std::bind
template<typename Callable, typename... Args>
struct function_traits<std::_Bind<Callable(Args...)>> 
    : function_traits<Callable> {};

using callback_id = size_t;

class EventBus {
public:
    EventBus(const EventBus&) = delete;
    EventBus(EventBus&&) = delete;
    EventBus& operator=(const EventBus&) = delete;
    EventBus& operator=(EventBus&&) = delete;
    enum class EventType;
    
    static EventBus& getInstance() {
        return instance;
    }

    void registerEvent(EventType eventName) {
        auto [it, inserted] = registered_events.emplace(std::move(eventName));
        if (inserted) {
            callbacks_map.try_emplace(*it).first->second.reserve(3);
        }
    }

    // subscribe with explicit template parameters
    template<typename... Args>
    callback_id subscribe(const EventType eventName, std::function<void(Args...)> callback) {
        if (!isEventRegistered(eventName)) {
            throw std::runtime_error("Event not registered: " + std::to_string(static_cast<int>(eventName)));
        }
        callback_id id = ++next_id;
        callbacks_map[eventName].emplace_back(CallbackWrapper{id, callback});
        return id;
    }

    // automatically derive the subscribe of callback type
    template<typename Callback>
    callback_id subscribe(EventType eventName, Callback&& callback) {
        using signature = typename function_traits<std::decay_t<Callback>>::signature;
        return subscribe(eventName, std::function<signature>(std::forward<Callback>(callback)));
    }

    // secure subscription version (auto-register events)
    template<typename... Args>
    callback_id subscribeSafe(const EventType eventName, std::function<void(Args...)> callback) {
        if (!isEventRegistered(eventName)) {
            registerEvent(eventName);
        }
        return subscribe(eventName, callback);
    }
    
    // automatically derived secure subscription version
    template<typename Callback>
    callback_id subscribeSafe(EventType eventName, Callback&& callback) {
        using signature = typename function_traits<std::decay_t<Callback>>::signature;
        return subscribeSafe(eventName, std::function<signature>(std::forward<Callback>(callback)));
    }

    template<typename... Args>
    void publish(EventType eventName, Args... args) {
        if (!isEventRegistered(eventName)) {
            throw std::runtime_error("Event not registered: " + std::to_string(static_cast<int>(eventName)));
        }
        
        auto args_tuple = std::make_shared<std::tuple<std::decay_t<Args>...>>(std::forward<Args>(args)...);

        for (auto& wrapper : callbacks_map[eventName]) {
            thread_pool->addTask([wrapper, args_tuple]() {
                try {
                    if (auto cb = std::any_cast<std::function<void(Args...)>>(&wrapper.callback)) {
                        std::apply(*cb, *args_tuple);
                    } 
                    else if (auto cb = std::any_cast<std::function<void()>>(&wrapper.callback)) {
                        (*cb)();
                    }
                } catch (...) {
                    std::cerr << "Callback execution failed for event: " << wrapper.id << "\n";
                }
            });
        }
    }

    bool isEventRegistered(const EventType eventName) const {
        return registered_events.find(eventName) != registered_events.end();
    }

    bool unsubscribe(const EventType eventName, callback_id id) {
        if (!isEventRegistered(eventName)) return false;
        auto& callbacks = callbacks_map[eventName];
        for (auto it = callbacks.begin(); it != callbacks.end(); ) {
            if (it->id == id) {
                it = callbacks.erase(it);
                return true;
            } else {
                ++it;
            }
        }
        return false;
    }
    void initModuleSubscribe();
    void registerAllEvents();
private:
    EventBus();
    ~EventBus();
    struct CallbackWrapper {
        callback_id id;
        std::any callback;
    };
    std::unordered_map<EventType, std::vector<CallbackWrapper>> callbacks_map;
    std::unordered_set<EventType> registered_events;
    std::atomic<callback_id> next_id{0};
    std::unique_ptr<ThreadPool<>> thread_pool;
    static EventBus instance;
};

enum class EventBus::EventType {
    Test_Event,
    MaxEnumValue
};


#endif