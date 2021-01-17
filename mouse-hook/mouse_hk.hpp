#pragma once

#include <Windows.h>

#include <unordered_map>
#include <cstdint>
#include <thread>
#include <atomic>
#include <mutex>

namespace mouse_hk // thread-safe mouse hook api
{
	enum class key_t : unsigned char
	{
		lbutton = 1 << 0, // 0b000'00001
		rbutton = 1 << 1, // 0b000'00010
		mbutton = 1 << 2, // 0b000'00100
		xbutton1 = 1 << 3, // 0b000'01000
		xbutton2 = 1 << 4, // 0b000'10000
	};

	struct m_pos { long x; long y; };

	namespace detail
	{
		using native_event_t = uint64_t; // (eg. WM_(LBUTTON/RBUTTON/MBUTTON/XBUTTON)_(DOWN/UP))

		struct mouse_event_t // internal representation of mouse events
		{
			key_t button;
			bool down;
		};

		inline static std::atomic<unsigned char> mouse_state = 0b0000'0000; // 0 << 0, default state
		inline static m_pos i_pos = {0, 0}; // default position
		inline static HHOOK hk_handle = nullptr;  // handle to low level mouse hook
		inline static std::mutex hk_handle_mutex; // synchronization primitive for hk_handle

		inline static const std::unordered_map<native_event_t, mouse_event_t> event_map = // maps native_event_t -> mouse_event_t
		{
			{WM_LBUTTONDOWN, {key_t::lbutton,  /* down */ true }},
			{WM_LBUTTONUP,   {key_t::lbutton,  /* up   */ false}},
			{WM_RBUTTONDOWN, {key_t::rbutton,  /* down */ true }},
			{WM_RBUTTONUP,   {key_t::rbutton,  /* up   */ false}},
			{WM_MBUTTONDOWN, {key_t::mbutton,  /* down */ true }},
			{WM_MBUTTONUP,   {key_t::mbutton,  /* up   */ false}},
			{WM_XBUTTONDOWN, {key_t::xbutton1, /* down */ true }},
			{WM_XBUTTONUP,   {key_t::xbutton1, /* up   */ false}}
		};

		inline static LRESULT CALLBACK ll_mouse_hk(_In_ const int code, _In_ const WPARAM wparam, _In_ const LPARAM lparam)
		{
			const auto hk_handle_lock = std::lock_guard{ hk_handle_mutex };

			const auto call_next_hk = [code, wparam, lparam]() { return ::CallNextHookEx(hk_handle, code, wparam, lparam); };

			if (code != HC_ACTION) // ignore non-mouse messages
				return call_next_hk();

			const auto event_info = reinterpret_cast<const MSLLHOOKSTRUCT*>(lparam);

			if (event_info->flags & LLMHF_INJECTED || /* redundant */ event_info->flags & LLMHF_LOWER_IL_INJECTED) // ignore injected messages
				return call_next_hk();

			try
			{
				auto event = event_map.at(wparam); // maps (wparam) native_event_t -> (event) mouse_event_t, throws std::out_of_range if event is unknown

				if (event.button == key_t::xbutton1 && static_cast<uint16_t>(event_info->mouseData >> 16 /* upper word */) & XBUTTON2) // handle xbutton2 properly
					event.button = key_t::xbutton2;

				mouse_state ^= (-static_cast<int8_t>(event.down) ^ mouse_state) & static_cast<std::underlying_type_t<key_t>>(event.button); // update internal mouse state
			}
			catch (const std::out_of_range&) {} // ignore unknown messages

			i_pos.x = event_info->pt.x;
			i_pos.y = event_info->pt.y;

			return call_next_hk();
		}

		inline static bool install_hk()
		{
			const auto hk_handle_lock = std::lock_guard{ hk_handle_mutex };

			if (hk_handle) // fail if hook is already installed
				return false;

			hk_handle = ::SetWindowsHookEx(WH_MOUSE_LL, &ll_mouse_hk, GetModuleHandle(nullptr), 0); // install hook

			return hk_handle; // report success or failure
		}

		inline static bool uninstall_hk()
		{
			const auto hk_handle_lock = std::lock_guard{ hk_handle_mutex };

			if (!hk_handle) // fail if hook is not installed
				return false;

			if (!::UnhookWindowsHookEx(hk_handle)) // uninstall hook
				return false;

			mouse_state = 0b0000'0000; // 0 << 0, restore to default state
			hk_handle = nullptr; // allow for hook to be reinstalled

			return true; // success
		}

		class hk_guard // RAII guard
		{
		public:
			hk_guard()
			{
				install_hk();
			}

			// copy constructor/assignment operator and move assignment operator deleted

			explicit hk_guard(const hk_guard&)  noexcept = delete;
			/* implicit */ hk_guard(hk_guard&&) noexcept = default; // default move assignment operator for unique_ptr

			hk_guard& operator=(const hk_guard&) noexcept = delete;
			hk_guard& operator=(hk_guard&&)      noexcept = delete;

			~hk_guard() noexcept
			{
				uninstall_hk();
			}
		};
	}

	inline auto acquire_hk_guard() -> std::unique_ptr<detail::hk_guard>
	{
		{
			const auto hk_handle_lock = std::lock_guard{ detail::hk_handle_mutex };

			if (detail::hk_handle) // guard already acquired, return dummy guard
				return { nullptr };
		} // hk_handle_lock released

		return std::make_unique<detail::hk_guard>(); // acquire RAII guard, install hook
	}

	inline bool state(key_t button) noexcept
	{
		return detail::mouse_state & static_cast<std::underlying_type_t<key_t>>(button); // query internal mouse state
	}

	inline m_pos get_pos() 
	{
		return detail::i_pos;
	}
}

namespace key_hk
{
	namespace detail
	{

		inline static HHOOK hk_handle = nullptr;  // handle to low level key hook
		inline static HKL kb_layout = nullptr;
		inline static std::mutex hk_handle_mutex; // synchronization primitive for hk_handle
		inline static std::vector<uint32_t> vk_keys;


		inline static LRESULT CALLBACK ll_key_hk(_In_ const int code, _In_ const WPARAM wparam, _In_ const LPARAM lparam)
		{
			const auto hk_handle_lock = std::lock_guard{ hk_handle_mutex };

			const auto call_next_hk = [code, wparam, lparam]() { return ::CallNextHookEx(hk_handle, code, wparam, lparam); };

			if (code != HC_ACTION) // ignore non-key messages
				return call_next_hk();

			const auto event_info = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lparam);

			if (event_info->flags & LLKHF_INJECTED || /* redundant */ event_info->flags & LLKHF_LOWER_IL_INJECTED) // ignore injected messages
				return call_next_hk();

			try
			{
				if (!(event_info->flags & 0x80))
				{
					if (!vk_keys.empty())
					{
						auto it = std::find(vk_keys.begin(), vk_keys.end(), event_info->vkCode);
						if(it != vk_keys.end())
							return call_next_hk();
					}
					vk_keys.push_back(event_info->vkCode);
				}
				else 
				{
					if (!vk_keys.empty())
					{
						auto it = std::find(vk_keys.begin(), vk_keys.end(), event_info->vkCode);
						if (it == vk_keys.end())
							return call_next_hk();
						vk_keys.erase(it);
					}
				}
			}
			catch (const std::out_of_range&) {} // ignore unknown messages and every error about the std::vector lmao

			return call_next_hk();
		}

		inline static bool install_hk()
		{
			const auto hk_handle_lock = std::lock_guard{ hk_handle_mutex };

			if (hk_handle) // fail if hook is already installed
				return false;


			kb_layout = LoadKeyboardLayoutA("04090409", KLF_ACTIVATE);

			hk_handle = ::SetWindowsHookEx(WH_KEYBOARD_LL, &ll_key_hk, GetModuleHandle(nullptr), 0); // install hook

			return hk_handle; // report success or failure
		}

		inline static bool uninstall_hk()
		{
			const auto hk_handle_lock = std::lock_guard{ hk_handle_mutex };

			if (!hk_handle) // fail if hook is not installed
				return false;

			if (!::UnhookWindowsHookEx(hk_handle)) // uninstall hook
				return false;

			vk_keys.clear(); // 0 << 0, restore to default state
			hk_handle = nullptr; // allow for hook to be reinstalled

			return true; // success
		}

		class key_hk_guard // RAII guard
		{
		public:
			key_hk_guard()
			{
				install_hk();
			}

			// copy constructor/assignment operator and move assignment operator deleted

			explicit key_hk_guard(const key_hk_guard&)  noexcept = delete;
			/* implicit */ key_hk_guard(key_hk_guard&&) noexcept = default; // default move assignment operator for unique_ptr

			key_hk_guard& operator=(const key_hk_guard&) noexcept = delete;
			key_hk_guard& operator=(key_hk_guard&&)      noexcept = delete;

			~key_hk_guard() noexcept
			{
				uninstall_hk();
			}
		};
	}

	inline auto acquire_hk_guard() -> std::unique_ptr<detail::key_hk_guard>
	{
		{
			const auto hk_handle_lock = std::lock_guard{ detail::hk_handle_mutex };

			if (detail::hk_handle) // guard already acquired, return dummy guard
				return { nullptr };
		} // hk_handle_lock released

		return std::make_unique<detail::key_hk_guard>(); // acquire RAII guard, install hook
	}

	inline auto get_string() -> std::string 
	{
		std::string result;

	}

	inline bool vk_state(uint32_t button) noexcept
	{
		for (auto key : detail::vk_keys)
		{
			if (key == button)
				return true;
		}
		return false;
	}
}

//for console apps without a message handler
class message_queue_thread // for console applications without message queues
{
public:
	explicit message_queue_thread() :
		thread_state_(thread_state_t::starting),
		message_queue_thread_(message_queue_fn, std::ref(thread_state_))
	{
		while (thread_state_ != thread_state_t::running) // wait for message_queue_thread_ to signal success 
		{
			if (thread_state_ == thread_state_t::terminated) // wait for termination and throw if message_queue_thread_ signals failure 
			{
				message_queue_thread_.join();
				throw std::runtime_error{ "message_queue_thread() failed to install hook" };
			}
		}
	}

	void terminate() noexcept
	{
		if (thread_state_ != thread_state_t::running) // exit if thread is already terminated
			return;

		thread_state_ = thread_state_t::terminating; // signal message_queue_thread_ to terminate

		message_queue_thread_.join(); // wait for message_queue_thread_ to terminate
	}

	// copy and move constructors/assignment operators deleted

	explicit message_queue_thread(const message_queue_thread&)  noexcept = delete;
	/* implicit */ message_queue_thread(message_queue_thread&&) noexcept = delete;

	message_queue_thread& operator=(const message_queue_thread&) noexcept = delete;
	message_queue_thread& operator=(message_queue_thread&&)      noexcept = delete;

	~message_queue_thread() noexcept
	{
		this->terminate();
	}

private:
	enum class thread_state_t
	{
		starting,
		running,
		terminating,
		terminated,
	};

	std::atomic<thread_state_t> thread_state_;
	std::thread message_queue_thread_;

	// ReSharper disable once CppParameterMayBeConst
	static void message_queue_fn(std::reference_wrapper<std::atomic<thread_state_t>> thread_state_ref)
	{
		auto& thread_state = thread_state_ref.get();

		{
			const auto hk_guard = mouse_hk::acquire_hk_guard();
			const auto key_hk_guard = key_hk::acquire_hk_guard();


			thread_state = hk_guard ? thread_state_t::running : thread_state_t::terminating; // signal success or failure
			thread_state = key_hk_guard ? thread_state_t::running : thread_state_t::terminating;

			MSG msg = { nullptr }; // NOLINT(clang-diagnostic-missing-field-initializers)
			while (thread_state == thread_state_t::running) // dispatch messages until signaled
			{
				if (::PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE) > 0)
				{
					::TranslateMessage(&msg);
					::DispatchMessage(&msg);
				}
			}
		} // hk_guard released

		thread_state = thread_state_t::terminated; // signal successful termination
	}
};